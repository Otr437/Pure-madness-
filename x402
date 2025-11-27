// X402 Protocol Starknet Backend - ENHANCED PRODUCTION IMPLEMENTATION
// Node.js + Starknet.js + PostgreSQL + Redis + Advanced Monitoring
// npm install express starknet@6 axios cors express-rate-limit helmet compression morgan sequelize pg redis winston bcrypt jsonwebtoken dotenv ioredis bull prometheus-api-metrics express-validator socket.io @sentry/node

const express = require('express');
const { Contract, Account, Provider, ec, stark, hash, CallData, RpcProvider, num } = require('starknet');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { Sequelize, DataTypes, Op } = require('sequelize');
const Redis = require('redis');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, query, param, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// ==================== CONFIGURATION ====================

const ENV = process.env.NODE_ENV || 'development';
const CONFIG = {
    PORT: process.env.PORT || 3402,
    HOST: process.env.HOST || '0.0.0.0',
    JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    JWT_EXPIRY: process.env.JWT_EXPIRY || '24h',
    ADMIN_API_KEY: process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex'),
    
    // Database
    DB_HOST: process.env.DB_HOST || 'localhost',
    DB_PORT: process.env.DB_PORT || 5432,
    DB_NAME: process.env.DB_NAME || 'x402_starknet',
    DB_USER: process.env.DB_USER || 'postgres',
    DB_PASS: process.env.DB_PASS || 'postgres',
    REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
    
    // Starknet Configuration
    STARKNET_RPC_URL: process.env.STARKNET_RPC_URL || 'https://starknet-mainnet.public.blastapi.io',
    STARKNET_FALLBACK_RPCS: (process.env.STARKNET_FALLBACK_RPCS || '').split(',').filter(Boolean),
    STARKNET_CHAIN_ID: process.env.STARKNET_CHAIN_ID || '0x534e5f4d41494e',
    X402_CONTRACT_ADDRESS: process.env.X402_CONTRACT_ADDRESS,
    TREASURY_ADDRESS: process.env.TREASURY_ADDRESS,
    TREASURY_PRIVATE_KEY: process.env.TREASURY_PRIVATE_KEY,
    CONTRACT_SECRET_KEY: process.env.CONTRACT_SECRET_KEY || crypto.randomBytes(32).toString('hex'),
    
    // Token Addresses on Starknet
    USDC_ADDRESS: process.env.USDC_ADDRESS || '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    ETH_ADDRESS: process.env.ETH_ADDRESS || '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
    STRK_ADDRESS: process.env.STRK_ADDRESS || '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
    USDT_ADDRESS: process.env.USDT_ADDRESS || '0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8',
    DAI_ADDRESS: process.env.DAI_ADDRESS || '0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3',
    
    // Rate Limiting
    RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
    RATE_LIMIT_MAX: 1000,
    ADMIN_RATE_LIMIT_MAX: 10000,
    PAYMENT_RATE_LIMIT: 100, // per window
    
    // Payment Limits
    MIN_PAYMENT_AMOUNT: BigInt(process.env.MIN_PAYMENT_AMOUNT || '1000000'), // 1 USDC
    MAX_PAYMENT_AMOUNT: BigInt(process.env.MAX_PAYMENT_AMOUNT || '100000000000'), // 100k USDC
    MIN_DEFERRED_AMOUNT: BigInt(process.env.MIN_DEFERRED_AMOUNT || '1000000'),
    MAX_DEFERRED_AMOUNT: BigInt(process.env.MAX_DEFERRED_AMOUNT || '10000000000'),
    MAX_DEFERRED_BALANCE: BigInt(process.env.MAX_DEFERRED_BALANCE || '50000000000'), // 50k USDC
    
    // Monitoring & Retry
    BLOCK_POLL_INTERVAL: parseInt(process.env.BLOCK_POLL_INTERVAL || '30000'), // 30s
    PAYMENT_CONFIRMATION_BLOCKS: parseInt(process.env.PAYMENT_CONFIRMATION_BLOCKS || '1'),
    MAX_RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 2000,
    TRANSACTION_TIMEOUT: 300000, // 5 minutes
    
    // Feature Flags
    ENABLE_WEBHOOKS: process.env.ENABLE_WEBHOOKS === 'true',
    ENABLE_METRICS: process.env.ENABLE_METRICS === 'true',
    ENABLE_WEBSOCKETS: process.env.ENABLE_WEBSOCKETS === 'true',
    ENABLE_AUTO_SETTLEMENT: process.env.ENABLE_AUTO_SETTLEMENT === 'true',
    
    // Webhook Configuration
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),
    WEBHOOK_RETRY_ATTEMPTS: 3,
    WEBHOOK_TIMEOUT: 10000,
};

// Token Configuration with Metadata
const SUPPORTED_TOKENS = {
    'USDC': {
        address: CONFIG.USDC_ADDRESS,
        decimals: 6,
        symbol: 'USDC',
        name: 'USD Coin',
        minAmount: '1000000', // 1 USDC
        maxAmount: '100000000000' // 100k USDC
    },
    'ETH': {
        address: CONFIG.ETH_ADDRESS,
        decimals: 18,
        symbol: 'ETH',
        name: 'Ethereum',
        minAmount: '100000000000000', // 0.0001 ETH
        maxAmount: '1000000000000000000000' // 1000 ETH
    },
    'STRK': {
        address: CONFIG.STRK_ADDRESS,
        decimals: 18,
        symbol: 'STRK',
        name: 'Starknet Token',
        minAmount: '1000000000000000000', // 1 STRK
        maxAmount: '1000000000000000000000' // 1000 STRK
    },
    'USDT': {
        address: CONFIG.USDT_ADDRESS,
        decimals: 6,
        symbol: 'USDT',
        name: 'Tether USD',
        minAmount: '1000000',
        maxAmount: '100000000000'
    },
    'DAI': {
        address: CONFIG.DAI_ADDRESS,
        decimals: 18,
        symbol: 'DAI',
        name: 'Dai Stablecoin',
        minAmount: '1000000000000000000',
        maxAmount: '100000000000000000000'
    }
};

// ==================== LOGGING ====================

if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs');
}

const logger = winston.createLogger({
    level: ENV === 'production' ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'x402-starknet-backend', version: '2.0.0' },
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 10485760,
            maxFiles: 10
        }),
        new winston.transports.File({ 
            filename: 'logs/payments.log',
            level: 'info',
            maxsize: 10485760,
            maxFiles: 10
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
            level: ENV === 'production' ? 'info' : 'debug'
        })
    ],
});

// ==================== DATABASE ====================

const sequelize = new Sequelize(CONFIG.DB_NAME, CONFIG.DB_USER, CONFIG.DB_PASS, {
    host: CONFIG.DB_HOST,
    port: CONFIG.DB_PORT,
    dialect: 'postgres',
    logging: (msg) => logger.debug(msg),
    pool: { 
        max: 20, 
        min: 5, 
        acquire: 60000, 
        idle: 10000 
    },
    retry: {
        max: 3
    }
});

// Payment Model
const Payment = sequelize.define('Payment', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    paymentId: { type: DataTypes.STRING, unique: true, allowNull: false, index: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    payer: { type: DataTypes.STRING, allowNull: false, index: true },
    amount: { type: DataTypes.STRING, allowNull: false },
    token: { type: DataTypes.STRING, allowNull: false, index: true },
    tokenSymbol: { type: DataTypes.STRING },
    status: { 
        type: DataTypes.ENUM('pending', 'confirmed', 'failed', 'settled', 'expired'), 
        defaultValue: 'pending',
        index: true
    },
    paymentType: { type: DataTypes.ENUM('immediate', 'deferred'), allowNull: false },
    resource: { type: DataTypes.STRING },
    txHash: { type: DataTypes.STRING, index: true },
    blockNumber: { type: DataTypes.BIGINT },
    confirmations: { type: DataTypes.INTEGER, defaultValue: 0 },
    metadata: { type: DataTypes.JSONB },
    errorMessage: { type: DataTypes.TEXT },
    retryCount: { type: DataTypes.INTEGER, defaultValue: 0 },
    expiresAt: { type: DataTypes.DATE },
    confirmedAt: { type: DataTypes.DATE },
    settledAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId', 'status'] },
        { fields: ['payer', 'status'] },
        { fields: ['status', 'createdAt'] },
        { fields: ['token', 'status'] },
        { fields: ['createdAt'] },
        { fields: ['expiresAt'] }
    ]
});

// Deferred Payment Model
const DeferredPayment = sequelize.define('DeferredPayment', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    payer: { type: DataTypes.STRING, index: true },
    amount: { type: DataTypes.STRING, allowNull: false },
    token: { type: DataTypes.STRING, allowNull: false },
    resource: { type: DataTypes.STRING },
    authorization: { type: DataTypes.STRING, unique: true, allowNull: false, index: true },
    signature: { type: DataTypes.STRING, allowNull: false },
    timestamp: { type: DataTypes.BIGINT, allowNull: false },
    settled: { type: DataTypes.BOOLEAN, defaultValue: false, index: true },
    settlementTx: { type: DataTypes.STRING },
    settlementAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
    metadata: { type: DataTypes.JSONB },
    expiresAt: { type: DataTypes.DATE },
    settledAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId', 'settled'] },
        { fields: ['payer', 'settled'] },
        { fields: ['settled', 'createdAt'] },
        { fields: ['authorization'] }
    ]
});

// Client Model - Track registered clients
const Client = sequelize.define('Client', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    clientId: { type: DataTypes.STRING, unique: true, allowNull: false, index: true },
    name: { type: DataTypes.STRING, allowNull: false },
    apiKey: { type: DataTypes.STRING, unique: true, allowNull: false },
    apiKeyHash: { type: DataTypes.STRING, allowNull: false },
    webhookUrl: { type: DataTypes.STRING },
    webhookSecret: { type: DataTypes.STRING },
    allowedOrigins: { type: DataTypes.ARRAY(DataTypes.STRING), defaultValue: [] },
    supportedTokens: { type: DataTypes.ARRAY(DataTypes.STRING), defaultValue: ['USDC', 'ETH', 'STRK'] },
    enableDeferred: { type: DataTypes.BOOLEAN, defaultValue: true },
    maxDeferredBalance: { type: DataTypes.STRING, defaultValue: CONFIG.MAX_DEFERRED_BALANCE.toString() },
    rateLimit: { type: DataTypes.INTEGER, defaultValue: 100 },
    isActive: { type: DataTypes.BOOLEAN, defaultValue: true, index: true },
    metadata: { type: DataTypes.JSONB },
    lastAccessAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId'] },
        { fields: ['isActive'] }
    ]
});

// Admin User Model
const AdminUser = sequelize.define('AdminUser', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    role: { 
        type: DataTypes.ENUM('superadmin', 'admin', 'finance', 'support', 'viewer'), 
        defaultValue: 'viewer' 
    },
    permissions: { type: DataTypes.JSONB, defaultValue: [] },
    isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
    lastLogin: { type: DataTypes.DATE },
    loginAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
    lockedUntil: { type: DataTypes.DATE },
    twoFactorEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
    twoFactorSecret: { type: DataTypes.STRING }
});

// Audit Log Model
const AuditLog = sequelize.define('AuditLog', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    action: { type: DataTypes.STRING, allowNull: false, index: true },
    resource: { type: DataTypes.STRING, allowNull: false, index: true },
    resourceId: { type: DataTypes.STRING },
    userId: { type: DataTypes.UUID, index: true },
    username: { type: DataTypes.STRING },
    userIp: { type: DataTypes.STRING },
    userAgent: { type: DataTypes.STRING },
    details: { type: DataTypes.JSONB },
    status: { type: DataTypes.ENUM('success', 'failure'), index: true },
    errorMessage: { type: DataTypes.TEXT },
    duration: { type: DataTypes.INTEGER }
}, {
    indexes: [
        { fields: ['action', 'createdAt'] },
        { fields: ['userId', 'createdAt'] },
        { fields: ['status', 'createdAt'] },
        { fields: ['createdAt'] }
    ]
});

// Contract Event Model
const ContractEvent = sequelize.define('ContractEvent', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    eventName: { type: DataTypes.STRING, allowNull: false, index: true },
    blockNumber: { type: DataTypes.BIGINT, allowNull: false, index: true },
    transactionHash: { type: DataTypes.STRING, allowNull: false, index: true },
    eventData: { type: DataTypes.JSONB, allowNull: false },
    processed: { type: DataTypes.BOOLEAN, defaultValue: false, index: true },
    processedAt: { type: DataTypes.DATE },
    retryCount: { type: DataTypes.INTEGER, defaultValue: 0 }
}, {
    indexes: [
        { fields: ['eventName', 'processed'] },
        { fields: ['blockNumber', 'processed'] },
        { fields: ['processed', 'createdAt'] }
    ]
});

// Webhook Delivery Model
const WebhookDelivery = sequelize.define('WebhookDelivery', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    webhookUrl: { type: DataTypes.STRING, allowNull: false },
    event: { type: DataTypes.STRING, allowNull: false },
    payload: { type: DataTypes.JSONB, allowNull: false },
    status: { 
        type: DataTypes.ENUM('pending', 'delivered', 'failed'), 
        defaultValue: 'pending',
        index: true
    },
    attempts: { type: DataTypes.INTEGER, defaultValue: 0 },
    responseStatus: { type: DataTypes.INTEGER },
    responseBody: { type: DataTypes.TEXT },
    errorMessage: { type: DataTypes.TEXT },
    nextRetryAt: { type: DataTypes.DATE },
    deliveredAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId', 'status'] },
        { fields: ['status', 'nextRetryAt'] },
        { fields: ['createdAt'] }
    ]
});

// Metrics Model - Store system metrics
const Metric = sequelize.define('Metric', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false, index: true },
    value: { type: DataTypes.FLOAT, allowNull: false },
    labels: { type: DataTypes.JSONB, defaultValue: {} },
    timestamp: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW }
}, {
    indexes: [
        { fields: ['name', 'timestamp'] },
        { fields: ['timestamp'] }
    ],
    timestamps: false
});

// Settlement Batch Model - Track batch settlements
const SettlementBatch = sequelize.define('SettlementBatch', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    token: { type: DataTypes.STRING, allowNull: false },
    totalAmount: { type: DataTypes.STRING, allowNull: false },
    paymentCount: { type: DataTypes.INTEGER, allowNull: false },
    txHash: { type: DataTypes.STRING },
    status: { 
        type: DataTypes.ENUM('pending', 'processing', 'completed', 'failed'), 
        defaultValue: 'pending' 
    },
    errorMessage: { type: DataTypes.TEXT },
    processedAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId', 'status'] },
        { fields: ['status', 'createdAt'] }
    ]
});

// ==================== REDIS CACHE ====================

const redisClient = Redis.createClient({ 
    url: CONFIG.REDIS_URL,
    socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 1000)
    }
});

redisClient.on('error', (err) => logger.error('Redis Client Error', err));
redisClient.on('connect', () => logger.info('Redis connected'));
redisClient.on('reconnecting', () => logger.warn('Redis reconnecting'));

redisClient.connect().catch(err => logger.error('Redis connection error:', err));

const cache = {
    set: async (key, value, ttl = 3600) => {
        try {
            await redisClient.set(key, JSON.stringify(value), { EX: ttl });
        } catch (error) {
            logger.error('Admin statistics error:', error);
            res.status(500).json({
                error: 'Failed to get statistics',
                protocol: 'x402'
            });
        }
    }
);

// Get Audit Logs (Admin)
app.get('/api/v1/admin/audit-logs',
    authenticateAdmin,
    requirePermission('audit:read'),
    validate([
        query('action').optional().isString(),
        query('userId').optional().isUUID(),
        query('startDate').optional().isISO8601(),
        query('endDate').optional().isISO8601(),
        query('limit').optional().isInt({ min: 1, max: 500 })
    ]),
    async (req, res) => {
        try {
            const { action, userId, startDate, endDate, limit = 100 } = req.query;
            
            const where = {};
            if (action) where.action = action;
            if (userId) where.userId = userId;
            if (startDate || endDate) {
                where.createdAt = {};
                if (startDate) where.createdAt[Op.gte] = new Date(startDate);
                if (endDate) where.createdAt[Op.lte] = new Date(endDate);
            }
            
            const logs = await AuditLog.findAll({
                where,
                order: [['createdAt', 'DESC']],
                limit: parseInt(limit)
            });
            
            res.json({
                protocol: 'x402',
                logs
            });
            
        } catch (error) {
            logger.error('Admin audit logs error:', error);
            res.status(500).json({
                error: 'Failed to get audit logs',
                protocol: 'x402'
            });
        }
    }
);

// Manage Clients (Admin)
app.post('/api/v1/admin/clients',
    authenticateAdmin,
    requirePermission('clients:write'),
    validate([
        body('name').isString().notEmpty(),
        body('clientId').isString().notEmpty(),
        body('webhookUrl').optional().isURL(),
        body('supportedTokens').optional().isArray(),
        body('enableDeferred').optional().isBoolean()
    ]),
    auditMiddleware('create_client', 'client'),
    async (req, res) => {
        try {
            const { name, clientId, webhookUrl, supportedTokens, enableDeferred } = req.body;
            
            // Check if client already exists
            const existing = await Client.findOne({ where: { clientId } });
            if (existing) {
                return res.status(409).json({
                    error: 'Client already exists',
                    protocol: 'x402'
                });
            }
            
            // Generate API key
            const apiKey = crypto.randomBytes(32).toString('hex');
            const apiKeyHash = await bcrypt.hash(apiKey, 10);
            
            const client = await Client.create({
                name,
                clientId,
                apiKey,
                apiKeyHash,
                webhookUrl,
                webhookSecret: crypto.randomBytes(32).toString('hex'),
                supportedTokens: supportedTokens || ['USDC', 'ETH', 'STRK'],
                enableDeferred: enableDeferred !== undefined ? enableDeferred : true
            });
            
            res.status(201).json({
                protocol: 'x402',
                client: {
                    id: client.id,
                    name: client.name,
                    clientId: client.clientId,
                    apiKey: apiKey, // Only shown once
                    webhookSecret: client.webhookSecret,
                    supportedTokens: client.supportedTokens,
                    enableDeferred: client.enableDeferred
                }
            });
            
        } catch (error) {
            logger.error('Admin create client error:', error);
            res.status(500).json({
                error: 'Failed to create client',
                protocol: 'x402'
            });
        }
    }
);

// List Clients (Admin)
app.get('/api/v1/admin/clients',
    authenticateAdmin,
    requirePermission('clients:read'),
    async (req, res) => {
        try {
            const clients = await Client.findAll({
                attributes: { exclude: ['apiKey', 'apiKeyHash', 'webhookSecret'] },
                order: [['createdAt', 'DESC']]
            });
            
            res.json({
                protocol: 'x402',
                clients
            });
            
        } catch (error) {
            logger.error('Admin list clients error:', error);
            res.status(500).json({
                error: 'Failed to list clients',
                protocol: 'x402'
            });
        }
    }
);

// Update Client (Admin)
app.put('/api/v1/admin/clients/:id',
    authenticateAdmin,
    requirePermission('clients:write'),
    validate([
        param('id').isUUID()
    ]),
    auditMiddleware('update_client', 'client'),
    async (req, res) => {
        try {
            const { id } = req.params;
            const updates = req.body;
            
            const client = await Client.findByPk(id);
            if (!client) {
                return res.status(404).json({
                    error: 'Client not found',
                    protocol: 'x402'
                });
            }
            
            // Don't allow updating sensitive fields directly
            delete updates.apiKey;
            delete updates.apiKeyHash;
            
            await client.update(updates);
            
            res.json({
                protocol: 'x402',
                client: {
                    id: client.id,
                    name: client.name,
                    clientId: client.clientId,
                    isActive: client.isActive,
                    supportedTokens: client.supportedTokens,
                    enableDeferred: client.enableDeferred
                }
            });
            
        } catch (error) {
            logger.error('Admin update client error:', error);
            res.status(500).json({
                error: 'Failed to update client',
                protocol: 'x402'
            });
        }
    }
);

// Rotate Client API Key (Admin)
app.post('/api/v1/admin/clients/:id/rotate-key',
    authenticateAdmin,
    requirePermission('clients:write'),
    validate([
        param('id').isUUID()
    ]),
    auditMiddleware('rotate_api_key', 'client'),
    async (req, res) => {
        try {
            const { id } = req.params;
            
            const client = await Client.findByPk(id);
            if (!client) {
                return res.status(404).json({
                    error: 'Client not found',
                    protocol: 'x402'
                });
            }
            
            const newApiKey = crypto.randomBytes(32).toString('hex');
            const newApiKeyHash = await bcrypt.hash(newApiKey, 10);
            
            await client.update({
                apiKey: newApiKey,
                apiKeyHash: newApiKeyHash
            });
            
            // Clear cache
            const cacheKeys = await cache.keys(`client:${client.clientId}:*`);
            for (const key of cacheKeys) {
                await cache.del(key);
            }
            
            res.json({
                protocol: 'x402',
                apiKey: newApiKey, // Only shown once
                message: 'API key rotated successfully'
            });
            
        } catch (error) {
            logger.error('Admin rotate API key error:', error);
            res.status(500).json({
                error: 'Failed to rotate API key',
                protocol: 'x402'
            });
        }
    }
);

// Get Metrics (Admin)
app.get('/api/v1/admin/metrics',
    authenticateAdmin,
    requirePermission('metrics:read'),
    validate([
        query('name').optional().isString(),
        query('startTime').optional().isISO8601(),
        query('endTime').optional().isISO8601()
    ]),
    async (req, res) => {
        try {
            const { name, startTime, endTime } = req.query;
            
            const metrics = await getMetrics(name, startTime, endTime);
            
            res.json({
                protocol: 'x402',
                metrics
            });
            
        } catch (error) {
            logger.error('Admin metrics error:', error);
            res.status(500).json({
                error: 'Failed to get metrics',
                protocol: 'x402'
            });
        }
    }
);

// Webhook Management (Admin)
app.get('/api/v1/admin/webhooks',
    authenticateAdmin,
    requirePermission('webhooks:read'),
    validate([
        query('clientId').optional().isString(),
        query('status').optional().isIn(['pending', 'delivered', 'failed']),
        query('limit').optional().isInt({ min: 1, max: 500 })
    ]),
    async (req, res) => {
        try {
            const { clientId, status, limit = 100 } = req.query;
            
            const where = {};
            if (clientId) where.clientId = clientId;
            if (status) where.status = status;
            
            const webhooks = await WebhookDelivery.findAll({
                where,
                order: [['createdAt', 'DESC']],
                limit: parseInt(limit)
            });
            
            res.json({
                protocol: 'x402',
                webhooks
            });
            
        } catch (error) {
            logger.error('Admin webhooks error:', error);
            res.status(500).json({
                error: 'Failed to get webhooks',
                protocol: 'x402'
            });
        }
    }
);

// Retry Failed Webhook
app.post('/api/v1/admin/webhooks/:id/retry',
    authenticateAdmin,
    requirePermission('webhooks:write'),
    validate([
        param('id').isUUID()
    ]),
    auditMiddleware('retry_webhook', 'webhook'),
    async (req, res) => {
        try {
            const { id } = req.params;
            
            const webhook = await WebhookDelivery.findByPk(id);
            if (!webhook) {
                return res.status(404).json({
                    error: 'Webhook not found',
                    protocol: 'x402'
                });
            }
            
            const client = await Client.findOne({ 
                where: { clientId: webhook.clientId } 
            });
            
            if (!client) {
                return res.status(404).json({
                    error: 'Client not found',
                    protocol: 'x402'
                });
            }
            
            await deliverWebhook(webhook, client.webhookSecret);
            
            res.json({
                protocol: 'x402',
                message: 'Webhook retry initiated',
                webhookId: webhook.id
            });
            
        } catch (error) {
            logger.error('Admin retry webhook error:', error);
            res.status(500).json({
                error: 'Failed to retry webhook',
                protocol: 'x402'
            });
        }
    }
);

// Manual Settlement (Admin)
app.post('/api/v1/admin/settlements/manual',
    authenticateAdmin,
    requirePermission('settlements:write'),
    validate([
        body('clientId').isString().notEmpty(),
        body('token').isString().notEmpty()
    ]),
    auditMiddleware('manual_settlement', 'settlement'),
    async (req, res) => {
        try {
            const { clientId, token } = req.body;
            
            const txHash = await settleDeferredPayments(clientId, token);
            
            res.json({
                protocol: 'x402',
                settlement: {
                    clientId,
                    token,
                    txHash,
                    status: 'processing'
                }
            });
            
        } catch (error) {
            logger.error('Admin manual settlement error:', error);
            res.status(500).json({
                error: 'Failed to settle payments',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// Get Settlement Batches (Admin)
app.get('/api/v1/admin/settlements',
    authenticateAdmin,
    requirePermission('settlements:read'),
    validate([
        query('clientId').optional().isString(),
        query('status').optional().isIn(['pending', 'processing', 'completed', 'failed']),
        query('limit').optional().isInt({ min: 1, max: 500 })
    ]),
    async (req, res) => {
        try {
            const { clientId, status, limit = 100 } = req.query;
            
            const where = {};
            if (clientId) where.clientId = clientId;
            if (status) where.status = status;
            
            const batches = await SettlementBatch.findAll({
                where,
                order: [['createdAt', 'DESC']],
                limit: parseInt(limit)
            });
            
            res.json({
                protocol: 'x402',
                batches
            });
            
        } catch (error) {
            logger.error('Admin settlements error:', error);
            res.status(500).json({
                error: 'Failed to get settlements',
                protocol: 'x402'
            });
        }
    }
);

// System Health Check (Admin)
app.get('/api/v1/admin/system/health',
    authenticateAdmin,
    requirePermission('system:read'),
    async (req, res) => {
        try {
            const dbHealthy = await sequelize.authenticate()
                .then(() => true)
                .catch(() => false);
            
            const redisHealthy = redisClient.isOpen;
            
            const starknetHealthy = await provider.getBlockNumber()
                .then(() => true)
                .catch(() => false);
            
            const blockNumber = await provider.getBlockNumber().catch(() => null);
            
            const pendingPayments = await Payment.count({ 
                where: { status: 'pending' } 
            });
            
            const failedWebhooks = await WebhookDelivery.count({
                where: { status: 'failed' }
            });
            
            const unsettledDeferred = await DeferredPayment.count({
                where: { settled: false }
            });
            
            res.json({
                protocol: 'x402',
                health: {
                    database: dbHealthy ? 'healthy' : 'unhealthy',
                    cache: redisHealthy ? 'healthy' : 'unhealthy',
                    starknet: starknetHealthy ? 'healthy' : 'unhealthy',
                    monitoring: isMonitoring ? 'active' : 'inactive'
                },
                stats: {
                    currentBlock: blockNumber,
                    lastProcessedBlock,
                    pendingPayments,
                    failedWebhooks,
                    unsettledDeferred
                },
                config: {
                    contractAddress: CONFIG.X402_CONTRACT_ADDRESS,
                    treasuryAddress: CONFIG.TREASURY_ADDRESS,
                    features: {
                        webhooks: CONFIG.ENABLE_WEBHOOKS,
                        metrics: CONFIG.ENABLE_METRICS,
                        autoSettlement: CONFIG.ENABLE_AUTO_SETTLEMENT
                    }
                }
            });
            
        } catch (error) {
            logger.error('Admin health check error:', error);
            res.status(500).json({
                error: 'Failed to get system health',
                protocol: 'x402'
            });
        }
    }
);

// Create Admin User (Superadmin Only)
app.post('/api/v1/admin/users',
    authenticateAdmin,
    requirePermission('users:write'),
    validate([
        body('username').isString().notEmpty(),
        body('email').isEmail(),
        body('password').isString().isLength({ min: 8 }),
        body('role').isIn(['admin', 'finance', 'support', 'viewer']),
        body('permissions').optional().isArray()
    ]),
    auditMiddleware('create_admin_user', 'admin_user'),
    async (req, res) => {
        try {
            const { username, email, password, role, permissions } = req.body;
            
            // Check if user exists
            const existing = await AdminUser.findOne({
                where: {
                    [Op.or]: [{ username }, { email }]
                }
            });
            
            if (existing) {
                return res.status(409).json({
                    error: 'User already exists',
                    protocol: 'x402'
                });
            }
            
            const passwordHash = await bcrypt.hash(password, 12);
            
            const user = await AdminUser.create({
                username,
                email,
                passwordHash,
                role,
                permissions: permissions || []
            });
            
            res.status(201).json({
                protocol: 'x402',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    permissions: user.permissions
                }
            });
            
        } catch (error) {
            logger.error('Admin create user error:', error);
            res.status(500).json({
                error: 'Failed to create admin user',
                protocol: 'x402'
            });
        }
    }
);

// Error Handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        requestId: req.requestId,
        path: req.path
    });
    
    res.status(err.status || 500).json({
        error: ENV === 'production' ? 'Internal server error' : err.message,
        protocol: 'x402',
        requestId: req.requestId
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not found',
        protocol: 'x402',
        path: req.path
    });
});

// ==================== INITIALIZATION & STARTUP ====================

async function initialize() {
    try {
        logger.info('Starting X402 Protocol Backend...');
        
        // Test database connection
        await sequelize.authenticate();
        logger.info('Database connection established');
        
        // Sync database models
        if (ENV === 'development') {
            await sequelize.sync({ alter: true });
            logger.info('Database models synchronized');
        }
        
        // Initialize Starknet
        const starknetReady = await initializeStarknet();
        if (!starknetReady) {
            throw new Error('Starknet initialization failed');
        }
        
        // Create default superadmin if none exists
        const adminCount = await AdminUser.count();
        if (adminCount === 0) {
            const defaultPassword = process.env.ADMIN_PASSWORD || 'changeme123!';
            const passwordHash = await bcrypt.hash(defaultPassword, 12);
            
            await AdminUser.create({
                username: 'superadmin',
                email: 'admin@x402.protocol',
                passwordHash,
                role: 'superadmin',
                permissions: ['*'],
                isActive: true
            });
            
            logger.warn('Default superadmin created - username: superadmin, password: changeme123!');
        }
        
        // Start event monitoring
        if (CONFIG.X402_CONTRACT_ADDRESS) {
            startEventMonitoring();
        }
        
        // Start auto settlement
        if (CONFIG.ENABLE_AUTO_SETTLEMENT) {
            startAutoSettlement();
        }
        
        // Start webhook retry worker
        if (CONFIG.ENABLE_WEBHOOKS) {
            setInterval(async () => {
                const failedWebhooks = await WebhookDelivery.findAll({
                    where: {
                        status: 'pending',
                        nextRetryAt: { [Op.lte]: new Date() }
                    },
                    limit: 10
                });
                
                for (const webhook of failedWebhooks) {
                    const client = await Client.findOne({ 
                        where: { clientId: webhook.clientId } 
                    });
                    
                    if (client) {
                        await deliverWebhook(webhook, client.webhookSecret);
                    }
                }
            }, 60000); // Every minute
        }
        
        // Start server
        const server = app.listen(CONFIG.PORT, CONFIG.HOST, () => {
            logger.info(`X402 Protocol Backend listening on ${CONFIG.HOST}:${CONFIG.PORT}`);
            logger.info(`Environment: ${ENV}`);
            logger.info(`Contract: ${CONFIG.X402_CONTRACT_ADDRESS}`);
        });
        
        // Graceful shutdown
        process.on('SIGTERM', async () => {
            logger.info('SIGTERM received, shutting down gracefully...');
            
            stopEventMonitoring();
            stopAutoSettlement();
            
            server.close(async () => {
                await sequelize.close();
                await redisClient.quit();
                logger.info('Server closed');
                process.exit(0);
            });
        });
        
        process.on('SIGINT', async () => {
            logger.info('SIGINT received, shutting down gracefully...');
            
            stopEventMonitoring();
            stopAutoSettlement();
            
            server.close(async () => {
                await sequelize.close();
                await redisClient.quit();
                logger.info('Server closed');
                process.exit(0);
            });
        });
        
    } catch (error) {
        logger.error('Initialization error:', error);
        process.exit(1);
    }
}

// Start the application
initialize().catch(err => {
    logger.error('Fatal error:', err);
    process.exit(1);
});

// ==================== EXPORTS ====================

module.exports = {
    app,
    sequelize,
    logger,
    cache,
    provider,
    x402Contract
};
            logger.error('Cache set error:', error);
        }
    },
    get: async (key) => {
        try {
            const data = await redisClient.get(key);
            return data ? JSON.parse(data) : null;
        } catch (error) {
            logger.error('Cache get error:', error);
            return null;
        }
    },
    del: async (key) => {
        try {
            await redisClient.del(key);
        } catch (error) {
            logger.error('Cache del error:', error);
        }
    },
    keys: async (pattern) => {
        try {
            return await redisClient.keys(pattern);
        } catch (error) {
            logger.error('Cache keys error:', error);
            return [];
        }
    },
    incr: async (key, ttl = 3600) => {
        try {
            const value = await redisClient.incr(key);
            await redisClient.expire(key, ttl);
            return value;
        } catch (error) {
            logger.error('Cache incr error:', error);
            return 0;
        }
    }
};

// ==================== MIDDLEWARE ====================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://starknet-mainnet.public.blastapi.io"],
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(cors({
    origin: (origin, callback) => {
        const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
            process.env.ALLOWED_ORIGINS.split(',') : [];
        
        if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'Payment-Authorization', 
        'Payment-Type', 
        'X-Admin-Key', 
        'X-Client-Id',
        'X-API-Key'
    ]
}));

// Rate Limiters
const generalLimiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.RATE_LIMIT_MAX,
    message: { error: 'Too many requests', protocol: 'x402', retryAfter: 900 },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
        res.status(429).json({
            error: 'Too many requests',
            protocol: 'x402',
            retryAfter: 900
        });
    }
});

const adminLimiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.ADMIN_RATE_LIMIT_MAX,
    message: { error: 'Too many admin requests', protocol: 'x402' },
    standardHeaders: true,
    legacyHeaders: false,
});

const paymentLimiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.PAYMENT_RATE_LIMIT,
    keyGenerator: (req) => req.headers['x-client-id'] || req.ip,
    message: { error: 'Payment rate limit exceeded', protocol: 'x402' }
});

app.use('/api/v1/', generalLimiter);
app.use('/api/v1/admin/', adminLimiter);
app.use('/api/v1/payments/', paymentLimiter);

// Request Logging
app.use(morgan('combined', {
    stream: fs.createWriteStream(path.join(__dirname, 'logs/access.log'), { flags: 'a' })
}));

app.use((req, res, next) => {
    req.requestId = crypto.randomUUID();
    req.startTime = Date.now();
    
    logger.info('HTTP Request', {
        requestId: req.requestId,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        clientId: req.headers['x-client-id']
    });
    
    next();
});

// Response Time Tracking
app.use((req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
        const duration = Date.now() - req.startTime;
        
        logger.info('HTTP Response', {
            requestId: req.requestId,
            statusCode: res.statusCode,
            duration,
            path: req.path
        });
        
        // Record metrics
        if (CONFIG.ENABLE_METRICS) {
            recordMetric('http_request_duration_ms', duration, {
                method: req.method,
                path: req.route?.path || req.path,
                status: res.statusCode
            });
        }
        
        // Store event in database
        await ContractEvent.create({
            eventName,
            blockNumber,
            transactionHash: txHash,
            eventData,
            processed: true,
            processedAt: new Date()
        });
        
        // Record metrics
        await recordMetric('contract_event_processed', 1, { eventName });
        
        logger.info('Contract event processed', {
            eventName,
            blockNumber,
            txHash
        });
        
    } catch (error) {
        logger.error('Process contract event error:', error);
        
        // Store failed event for retry
        await ContractEvent.create({
            eventName: 'unknown',
            blockNumber,
            transactionHash: txHash,
            eventData: event,
            processed: false,
            retryCount: 0
        }).catch(err => logger.error('Store failed event error:', err));
    }
}

// ==================== AUTO SETTLEMENT ====================

let autoSettlementInterval;

async function startAutoSettlement() {
    if (!CONFIG.ENABLE_AUTO_SETTLEMENT) {
        logger.info('Auto settlement disabled');
        return;
    }
    
    logger.info('Starting auto settlement');
    
    // Run every hour
    autoSettlementInterval = setInterval(async () => {
        try {
            await processAutoSettlement();
        } catch (error) {
            logger.error('Auto settlement cycle error:', error);
        }
    }, 3600000);
    
    // Run immediately on start
    setTimeout(() => processAutoSettlement(), 5000);
}

async function stopAutoSettlement() {
    if (autoSettlementInterval) {
        clearInterval(autoSettlementInterval);
        logger.info('Auto settlement stopped');
    }
}

async function processAutoSettlement() {
    try {
        logger.info('Processing auto settlement');
        
        // Get clients with unsettled deferred payments
        const clientsWithDeferred = await DeferredPayment.findAll({
            where: { settled: false },
            attributes: ['clientId'],
            group: ['clientId'],
            raw: true
        });
        
        for (const { clientId } of clientsWithDeferred) {
            try {
                const balance = await getDeferredBalance(clientId);
                
                // Settle if balance exceeds threshold (e.g., 1000 USDC)
                if (BigInt(balance) >= 1000000000n) { // 1000 USDC
                    logger.info(`Auto settling for client ${clientId}, balance: ${balance}`);
                    await settleDeferredPayments(clientId, 'USDC');
                }
            } catch (error) {
                logger.error(`Auto settlement error for client ${clientId}:`, error);
            }
        }
        
        await recordMetric('auto_settlement_run', 1);
        
    } catch (error) {
        logger.error('Process auto settlement error:', error);
    }
}

async function getDeferredBalance(clientId) {
    const cacheKey = `deferred_balance:${clientId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;
    
    try {
        const balance = await retryContractCall(async () => {
            const result = await x402Contract.get_deferred_balance(stringToFelt(clientId));
            return parseUint256(result).toString();
        });
        
        await cache.set(cacheKey, balance, 300);
        return balance;
    } catch (error) {
        logger.error('Get deferred balance error:', error);
        return '0';
    }
}

async function settleDeferredPayments(clientId, tokenSymbol) {
    try {
        const tokenInfo = getTokenInfo(tokenSymbol);
        if (!tokenInfo) {
            throw new Error('Unsupported token');
        }
        
        const batch = await SettlementBatch.create({
            clientId,
            token: tokenInfo.address,
            totalAmount: '0',
            paymentCount: 0,
            status: 'processing'
        });
        
        const tx = await retryContractCall(async () => {
            return await x402Contract.settle_deferred_payments(
                stringToFelt(clientId),
                tokenInfo.address
            );
        });
        
        const receipt = await provider.waitForTransaction(tx.transaction_hash, {
            successStates: ['ACCEPTED_ON_L2', 'ACCEPTED_ON_L1']
        });
        
        await batch.update({
            txHash: tx.transaction_hash,
            status: 'completed',
            processedAt: new Date()
        });
        
        // Clear cache
        await cache.del(`deferred_balance:${clientId}`);
        
        logger.info('Deferred payments settled', {
            clientId,
            txHash: tx.transaction_hash
        });
        
        return tx.transaction_hash;
        
    } catch (error) {
        logger.error('Settle deferred payments error:', error);
        throw error;
    }
}

// ==================== API ENDPOINTS ====================

// Health Check
app.get('/health', async (req, res) => {
    try {
        const dbHealthy = await sequelize.authenticate()
            .then(() => true)
            .catch(() => false);
        
        const redisHealthy = redisClient.isOpen;
        
        const starknetHealthy = await provider.getBlockNumber()
            .then(() => true)
            .catch(() => false);
        
        const healthy = dbHealthy && redisHealthy && starknetHealthy;
        
        res.status(healthy ? 200 : 503).json({
            status: healthy ? 'healthy' : 'unhealthy',
            protocol: 'x402',
            version: '2.0.0',
            timestamp: new Date().toISOString(),
            services: {
                database: dbHealthy ? 'up' : 'down',
                cache: redisHealthy ? 'up' : 'down',
                starknet: starknetHealthy ? 'up' : 'down'
            }
        });
    } catch (error) {
        logger.error('Health check error:', error);
        res.status(503).json({
            status: 'unhealthy',
            protocol: 'x402',
            error: error.message
        });
    }
});

// Get System Status
app.get('/api/v1/status', async (req, res) => {
    try {
        const blockNumber = await provider.getBlockNumber();
        const chainId = await provider.getChainId();
        
        const totalPayments = await Payment.count();
        const pendingPayments = await Payment.count({ where: { status: 'pending' } });
        const confirmedPayments = await Payment.count({ where: { status: 'confirmed' } });
        
        const totalDeferred = await DeferredPayment.count();
        const unsettledDeferred = await DeferredPayment.count({ where: { settled: false } });
        
        const prices = await getTokenPrices();
        
        res.json({
            protocol: 'x402',
            version: '2.0.0',
            network: {
                chainId,
                blockNumber,
                lastProcessedBlock,
                contractAddress: CONFIG.X402_CONTRACT_ADDRESS
            },
            statistics: {
                totalPayments,
                pendingPayments,
                confirmedPayments,
                totalDeferred,
                unsettledDeferred
            },
            tokens: SUPPORTED_TOKENS,
            prices,
            features: {
                webhooks: CONFIG.ENABLE_WEBHOOKS,
                metrics: CONFIG.ENABLE_METRICS,
                autoSettlement: CONFIG.ENABLE_AUTO_SETTLEMENT
            }
        });
    } catch (error) {
        logger.error('Status endpoint error:', error);
        res.status(500).json({
            error: 'Failed to get status',
            protocol: 'x402'
        });
    }
});

// Get Supported Tokens
app.get('/api/v1/tokens', async (req, res) => {
    try {
        const prices = await getTokenPrices();
        
        const tokens = Object.values(SUPPORTED_TOKENS).map(token => ({
            ...token,
            price: prices[token.symbol]
        }));
        
        res.json({
            protocol: 'x402',
            tokens
        });
    } catch (error) {
        logger.error('Tokens endpoint error:', error);
        res.status(500).json({
            error: 'Failed to get tokens',
            protocol: 'x402'
        });
    }
});

// Create Payment Request (Client Authenticated)
app.post('/api/v1/payments/create',
    authenticateClient,
    validate([
        body('amount').isString().notEmpty(),
        body('token').isString().notEmpty(),
        body('resource').optional().isString(),
        body('metadata').optional().isObject()
    ]),
    auditMiddleware('create_payment', 'payment'),
    async (req, res) => {
        try {
            const { amount, token, resource, metadata } = req.body;
            const clientId = req.client.clientId;
            
            // Validate token
            const tokenInfo = getTokenInfo(token);
            if (!tokenInfo) {
                return res.status(400).json({
                    error: 'Unsupported token',
                    protocol: 'x402'
                });
            }
            
            // Validate amount
            const amountBn = BigInt(amount);
            if (amountBn < BigInt(tokenInfo.minAmount) || amountBn > BigInt(tokenInfo.maxAmount)) {
                return res.status(400).json({
                    error: 'Invalid amount',
                    protocol: 'x402',
                    min: tokenInfo.minAmount,
                    max: tokenInfo.maxAmount
                });
            }
            
            // Create payment on-chain
            const tx = await retryContractCall(async () => {
                return await x402Contract.create_payment_request(
                    toUint256(amount),
                    tokenInfo.address,
                    stringToFelt(resource || ''),
                    stringToFelt(clientId)
                );
            });
            
            const receipt = await provider.waitForTransaction(tx.transaction_hash);
            
            // Extract payment ID from events
            const paymentCreatedEvent = receipt.events?.find(
                e => e.keys[0] === hash.getSelectorFromName('PaymentCreated')
            );
            
            const paymentId = paymentCreatedEvent?.keys[1] || crypto.randomUUID();
            
            // Create payment record
            const payment = await Payment.create({
                paymentId,
                clientId,
                payer: '0x0', // Will be set when paid
                amount,
                token: tokenInfo.address,
                tokenSymbol: tokenInfo.symbol,
                status: 'pending',
                paymentType: 'immediate',
                resource,
                txHash: tx.transaction_hash,
                metadata,
                expiresAt: new Date(Date.now() + 3600000) // 1 hour
            });
            
            await recordMetric('payment_created', 1, {
                clientId,
                token: tokenInfo.symbol
            });
            
            res.status(201).json({
                protocol: 'x402',
                payment: {
                    id: payment.id,
                    paymentId,
                    amount,
                    token: tokenInfo.symbol,
                    status: 'pending',
                    txHash: tx.transaction_hash,
                    expiresAt: payment.expiresAt
                }
            });
            
        } catch (error) {
            logger.error('Create payment error:', error);
            res.status(500).json({
                error: 'Failed to create payment',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// Process Immediate Payment
app.post('/api/v1/payments/:paymentId/process',
    authenticateClient,
    validate([
        param('paymentId').isString().notEmpty(),
        body('payer').isString().notEmpty()
    ]),
    auditMiddleware('process_payment', 'payment'),
    async (req, res) => {
        try {
            const { paymentId } = req.params;
            const { payer } = req.body;
            
            const payment = await Payment.findOne({
                where: { paymentId, clientId: req.client.clientId }
            });
            
            if (!payment) {
                return res.status(404).json({
                    error: 'Payment not found',
                    protocol: 'x402'
                });
            }
            
            if (payment.status !== 'pending') {
                return res.status(400).json({
                    error: 'Payment already processed',
                    protocol: 'x402',
                    status: payment.status
                });
            }
            
            // Process payment on-chain
            const tx = await retryContractCall(async () => {
                return await x402Contract.process_immediate_payment(
                    paymentId,
                    payment.token,
                    toUint256(payment.amount)
                );
            });
            
            await provider.waitForTransaction(tx.transaction_hash);
            
            await payment.update({
                payer,
                status: 'confirmed',
                confirmedAt: new Date(),
                txHash: tx.transaction_hash
            });
            
            await recordMetric('payment_processed', 1, {
                clientId: req.client.clientId,
                token: payment.tokenSymbol
            });
            
            res.json({
                protocol: 'x402',
                payment: {
                    id: payment.id,
                    paymentId,
                    status: 'confirmed',
                    txHash: tx.transaction_hash
                }
            });
            
        } catch (error) {
            logger.error('Process payment error:', error);
            res.status(500).json({
                error: 'Failed to process payment',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// Verify Payment
app.get('/api/v1/payments/:paymentId/verify',
    authenticateClient,
    validate([
        param('paymentId').isString().notEmpty(),
        query('payer').isString().notEmpty()
    ]),
    async (req, res) => {
        try {
            const { paymentId } = req.params;
            const { payer } = req.query;
            
            const payment = await Payment.findOne({
                where: { paymentId, clientId: req.client.clientId }
            });
            
            if (!payment) {
                return res.status(404).json({
                    error: 'Payment not found',
                    protocol: 'x402'
                });
            }
            
            // Verify on-chain
            const verified = await verifyOnChainPayment(paymentId, payer);
            
            res.json({
                protocol: 'x402',
                verified,
                payment: {
                    id: payment.id,
                    paymentId,
                    status: payment.status,
                    amount: payment.amount,
                    token: payment.tokenSymbol,
                    confirmedAt: payment.confirmedAt
                }
            });
            
        } catch (error) {
            logger.error('Verify payment error:', error);
            res.status(500).json({
                error: 'Failed to verify payment',
                protocol: 'x402'
            });
        }
    }
);

// Get Payment Details
app.get('/api/v1/payments/:paymentId',
    authenticateClient,
    validate([
        param('paymentId').isString().notEmpty()
    ]),
    async (req, res) => {
        try {
            const { paymentId } = req.params;
            
            const payment = await Payment.findOne({
                where: { paymentId, clientId: req.client.clientId }
            });
            
            if (!payment) {
                return res.status(404).json({
                    error: 'Payment not found',
                    protocol: 'x402'
                });
            }
            
            res.json({
                protocol: 'x402',
                payment: {
                    id: payment.id,
                    paymentId: payment.paymentId,
                    amount: payment.amount,
                    token: payment.tokenSymbol,
                    status: payment.status,
                    payer: payment.payer,
                    resource: payment.resource,
                    txHash: payment.txHash,
                    blockNumber: payment.blockNumber,
                    metadata: payment.metadata,
                    createdAt: payment.createdAt,
                    confirmedAt: payment.confirmedAt,
                    expiresAt: payment.expiresAt
                }
            });
            
        } catch (error) {
            logger.error('Get payment error:', error);
            res.status(500).json({
                error: 'Failed to get payment',
                protocol: 'x402'
            });
        }
    }
);

// List Payments
app.get('/api/v1/payments',
    authenticateClient,
    validate([
        query('status').optional().isIn(['pending', 'confirmed', 'failed', 'settled', 'expired']),
        query('token').optional().isString(),
        query('limit').optional().isInt({ min: 1, max: 100 }),
        query('offset').optional().isInt({ min: 0 })
    ]),
    async (req, res) => {
        try {
            const { status, token, limit = 20, offset = 0 } = req.query;
            
            const where = { clientId: req.client.clientId };
            if (status) where.status = status;
            if (token) {
                const tokenInfo = getTokenInfo(token);
                if (tokenInfo) where.token = tokenInfo.address;
            }
            
            const { count, rows: payments } = await Payment.findAndCountAll({
                where,
                order: [['createdAt', 'DESC']],
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
            
            res.json({
                protocol: 'x402',
                total: count,
                limit: parseInt(limit),
                offset: parseInt(offset),
                payments: payments.map(p => ({
                    id: p.id,
                    paymentId: p.paymentId,
                    amount: p.amount,
                    token: p.tokenSymbol,
                    status: p.status,
                    payer: p.payer,
                    resource: p.resource,
                    createdAt: p.createdAt,
                    confirmedAt: p.confirmedAt
                }))
            });
            
        } catch (error) {
            logger.error('List payments error:', error);
            res.status(500).json({
                error: 'Failed to list payments',
                protocol: 'x402'
            });
        }
    }
);

// Authorize Deferred Payment
app.post('/api/v1/deferred/authorize',
    authenticateClient,
    validate([
        body('amount').isString().notEmpty(),
        body('resource').optional().isString(),
        body('metadata').optional().isObject()
    ]),
    auditMiddleware('authorize_deferred', 'deferred_payment'),
    async (req, res) => {
        try {
            const { amount, resource, metadata } = req.body;
            const clientId = req.client.clientId;
            
            if (!req.client.enableDeferred) {
                return res.status(403).json({
                    error: 'Deferred payments not enabled',
                    protocol: 'x402'
                });
            }
            
            // Validate amount
            const amountBn = BigInt(amount);
            if (amountBn < CONFIG.MIN_DEFERRED_AMOUNT || amountBn > CONFIG.MAX_DEFERRED_AMOUNT) {
                return res.status(400).json({
                    error: 'Invalid amount',
                    protocol: 'x402'
                });
            }
            
            // Check current balance
            const currentBalance = await getDeferredBalance(clientId);
            if (BigInt(currentBalance) + amountBn > BigInt(req.client.maxDeferredBalance)) {
                return res.status(400).json({
                    error: 'Would exceed max deferred balance',
                    protocol: 'x402',
                    currentBalance,
                    maxBalance: req.client.maxDeferredBalance
                });
            }
            
            const timestamp = Date.now();
            const authorization = generatePaymentAuthorization(
                clientId,
                amount,
                resource || '',
                timestamp
            );
            
            // Authorize on-chain
            const tx = await retryContractCall(async () => {
                return await x402Contract.authorize_deferred_payment(
                    stringToFelt(clientId),
                    toUint256(amount),
                    stringToFelt(resource || '')
                );
            });
            
            await provider.waitForTransaction(tx.transaction_hash);
            
            const deferred = await DeferredPayment.create({
                clientId,
                amount,
                resource,
                authorization,
                signature: '0x0',
                timestamp,
                settled: false,
                metadata,
                expiresAt: new Date(Date.now() + 86400000) // 24 hours
            });
            
            await recordMetric('deferred_authorized', 1, { clientId });
            
            res.status(201).json({
                protocol: 'x402',
                deferred: {
                    id: deferred.id,
                    authorization,
                    amount,
                    timestamp,
                    expiresAt: deferred.expiresAt
                }
            });
            
        } catch (error) {
            logger.error('Authorize deferred error:', error);
            res.status(500).json({
                error: 'Failed to authorize deferred payment',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// Commit Deferred Payment
app.post('/api/v1/deferred/commit',
    authenticateClient,
    validate([
        body('authorization').isString().notEmpty(),
        body('signature').isString().notEmpty()
    ]),
    auditMiddleware('commit_deferred', 'deferred_payment'),
    async (req, res) => {
        try {
            const { authorization, signature } = req.body;
            
            const deferred = await DeferredPayment.findOne({
                where: { 
                    authorization,
                    clientId: req.client.clientId,
                    settled: false
                }
            });
            
            if (!deferred) {
                return res.status(404).json({
                    error: 'Deferred payment not found',
                    protocol: 'x402'
                });
            }
            
            // Commit on-chain
            const tx = await retryContractCall(async () => {
                return await x402Contract.commit_deferred_payment(
                    stringToFelt(deferred.clientId),
                    toUint256(deferred.amount),
                    stringToFelt(deferred.resource || ''),
                    authorization,
                    signature
                );
            });
            
            await provider.waitForTransaction(tx.transaction_hash);
            
            await deferred.update({ signature });
            
            await recordMetric('deferred_committed', 1, {
                clientId: req.client.clientId
            });
            
            res.json({
                protocol: 'x402',
                deferred: {
                    id: deferred.id,
                    authorization: deferred.authorization,
                    committed: true
                }
            });
            
        } catch (error) {
            logger.error('Commit deferred error:', error);
            res.status(500).json({
                error: 'Failed to commit deferred payment',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// Get Deferred Balance
app.get('/api/v1/deferred/balance',
    authenticateClient,
    async (req, res) => {
        try {
            const balance = await getDeferredBalance(req.client.clientId);
            
            const unsettled = await DeferredPayment.sum('amount', {
                where: {
                    clientId: req.client.clientId,
                    settled: false
                }
            }) || '0';
            
            res.json({
                protocol: 'x402',
                balance: {
                    onChain: balance,
                    pending: unsettled.toString(),
                    maxBalance: req.client.maxDeferredBalance
                }
            });
            
        } catch (error) {
            logger.error('Get deferred balance error:', error);
            res.status(500).json({
                error: 'Failed to get deferred balance',
                protocol: 'x402'
            });
        }
    }
);

// Settle Deferred Payments
app.post('/api/v1/deferred/settle',
    authenticateClient,
    validate([
        body('token').isString().notEmpty()
    ]),
    auditMiddleware('settle_deferred', 'deferred_payment'),
    async (req, res) => {
        try {
            const { token } = req.body;
            
            const txHash = await settleDeferredPayments(req.client.clientId, token);
            
            await recordMetric('deferred_settled', 1, {
                clientId: req.client.clientId,
                token
            });
            
            res.json({
                protocol: 'x402',
                settlement: {
                    txHash,
                    token,
                    status: 'processing'
                }
            });
            
        } catch (error) {
            logger.error('Settle deferred error:', error);
            res.status(500).json({
                error: 'Failed to settle deferred payments',
                protocol: 'x402',
                message: error.message
            });
        }
    }
);

// ==================== ADMIN ENDPOINTS ====================

// Admin Login
app.post('/api/v1/admin/login',
    validate([
        body('username').isString().notEmpty(),
        body('password').isString().notEmpty()
    ]),
    async (req, res) => {
        try {
            const { username, password } = req.body;
            
            const admin = await AdminUser.findOne({ where: { username } });
            
            if (!admin) {
                return res.status(401).json({
                    error: 'Invalid credentials',
                    protocol: 'x402'
                });
            }
            
            // Check if account is locked
            if (admin.lockedUntil && admin.lockedUntil > new Date()) {
                return res.status(423).json({
                    error: 'Account is locked',
                    protocol: 'x402',
                    lockedUntil: admin.lockedUntil
                });
            }
            
            const validPassword = await bcrypt.compare(password, admin.passwordHash);
            
            if (!validPassword) {
                await admin.update({
                    loginAttempts: admin.loginAttempts + 1,
                    lockedUntil: admin.loginAttempts >= 4 ? 
                        new Date(Date.now() + 1800000) : null // Lock for 30 min
                });
                
                return res.status(401).json({
                    error: 'Invalid credentials',
                    protocol: 'x402'
                });
            }
            
            // Reset login attempts
            await admin.update({
                loginAttempts: 0,
                lockedUntil: null,
                lastLogin: new Date()
            });
            
            const token = jwt.sign(
                { userId: admin.id, role: admin.role },
                CONFIG.JWT_SECRET,
                { expiresIn: CONFIG.JWT_EXPIRY }
            );
            
            res.json({
                protocol: 'x402',
                token,
                admin: {
                    id: admin.id,
                    username: admin.username,
                    role: admin.role,
                    permissions: admin.permissions
                }
            });
            
        } catch (error) {
            logger.error('Admin login error:', error);
            res.status(500).json({
                error: 'Login failed',
                protocol: 'x402'
            });
        }
    }
);

// Get All Payments (Admin)
app.get('/api/v1/admin/payments',
    authenticateAdmin,
    requirePermission('payments:read'),
    validate([
        query('clientId').optional().isString(),
        query('status').optional().isIn(['pending', 'confirmed', 'failed', 'settled', 'expired']),
        query('limit').optional().isInt({ min: 1, max: 1000 }),
        query('offset').optional().isInt({ min: 0 })
    ]),
    async (req, res) => {
        try {
            const { clientId, status, limit = 50, offset = 0 } = req.query;
            
            const where = {};
            if (clientId) where.clientId = clientId;
            if (status) where.status = status;
            
            const { count, rows: payments } = await Payment.findAndCountAll({
                where,
                order: [['createdAt', 'DESC']],
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
            
            res.json({
                protocol: 'x402',
                total: count,
                payments
            });
            
        } catch (error) {
            logger.error('Admin get payments error:', error);
            res.status(500).json({
                error: 'Failed to get payments',
                protocol: 'x402'
            });
        }
    }
);

// Get Statistics (Admin)
app.get('/api/v1/admin/statistics',
    authenticateAdmin,
    requirePermission('stats:read'),
    async (req, res) => {
        try {
            const totalPayments = await Payment.count();
            const totalVolume = await Payment.sum('amount', {
                where: { status: 'confirmed' }
            });
            
            const paymentsByStatus = await Payment.findAll({
                attributes: [
                    'status',
                    [sequelize.fn('COUNT', sequelize.col('id')), 'count']
                ],
                group: ['status'],
                raw: true
            });
            
            const paymentsByToken = await Payment.findAll({
                attributes: [
                    'tokenSymbol',
                    [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
                    [sequelize.fn('SUM', sequelize.cast(sequelize.col('amount'), 'BIGINT')), 'volume']
                ],
                where: { status: 'confirmed' },
                group: ['tokenSymbol'],
                raw: true
            });
            
            const recentPayments = await Payment.findAll({
                where: {
                    createdAt: {
                        [Op.gte]: new Date(Date.now() - 86400000) // Last 24h
                    }
                },
                attributes: [
                    [sequelize.fn('COUNT', sequelize.col('id')), 'count']
                ],
                raw: true
            });
            
            res.json({
                protocol: 'x402',
                statistics: {
                    totalPayments,
                    totalVolume: totalVolume || '0',
                    paymentsByStatus,
                    paymentsByToken,
                    last24Hours: recentPayments[0]?.count || 0
                }
            });
            
        } catch (error) {originalSend.call(this, data);
    };
    
    next();
});

// ==================== AUTH MIDDLEWARE ====================

// API Key Authentication for Clients
const authenticateClient = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const clientId = req.headers['x-client-id'];
        
        if (!apiKey || !clientId) {
            return res.status(401).json({ 
                error: 'Missing authentication credentials', 
                protocol: 'x402' 
            });
        }
        
        const cacheKey = `client:${clientId}:${apiKey}`;
        let client = await cache.get(cacheKey);
        
        if (!client) {
            client = await Client.findOne({ 
                where: { clientId, isActive: true } 
            });
            
            if (!client) {
                return res.status(401).json({ 
                    error: 'Invalid client credentials', 
                    protocol: 'x402' 
                });
            }
            
            const validKey = await bcrypt.compare(apiKey, client.apiKeyHash);
            if (!validKey) {
                return res.status(401).json({ 
                    error: 'Invalid API key', 
                    protocol: 'x402' 
                });
            }
            
            await cache.set(cacheKey, client.toJSON(), 3600);
        }
        
        // Update last access
        Client.update(
            { lastAccessAt: new Date() },
            { where: { id: client.id } }
        ).catch(err => logger.error('Update lastAccessAt error:', err));
        
        req.client = client;
        next();
    } catch (error) {
        logger.error('Client authentication error:', error);
        res.status(401).json({ 
            error: 'Authentication failed', 
            protocol: 'x402' 
        });
    }
};

// Admin Authentication
const authenticateAdmin = async (req, res, next) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        const authHeader = req.headers['authorization'];
        
        // Check for master admin key
        if (adminKey && adminKey === CONFIG.ADMIN_API_KEY) {
            req.admin = { 
                role: 'superadmin', 
                permissions: ['*'],
                username: 'system'
            };
            return next();
        }
        
        // Check for JWT token
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
            
            const adminUser = await AdminUser.findByPk(decoded.userId);
            if (adminUser && adminUser.isActive) {
                // Check if account is locked
                if (adminUser.lockedUntil && adminUser.lockedUntil > new Date()) {
                    return res.status(423).json({ 
                        error: 'Account is locked', 
                        protocol: 'x402',
                        lockedUntil: adminUser.lockedUntil
                    });
                }
                
                req.admin = adminUser;
                return next();
            }
        }
        
        res.status(401).json({ 
            error: 'Admin authentication required', 
            protocol: 'x402' 
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expired',
                protocol: 'x402'
            });
        }
        logger.error('Admin authentication error:', error);
        res.status(401).json({ 
            error: 'Invalid admin credentials', 
            protocol: 'x402' 
        });
    }
};

// Permission Check Middleware
const requirePermission = (...permissions) => {
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({ 
                error: 'Authentication required', 
                protocol: 'x402' 
            });
        }
        
        // Superadmin has all permissions
        if (req.admin.role === 'superadmin' || req.admin.permissions === '*') {
            return next();
        }
        
        // Check if user has required permission
        const userPermissions = Array.isArray(req.admin.permissions) ? 
            req.admin.permissions : [];
        
        const hasPermission = permissions.some(perm => 
            userPermissions.includes(perm) || userPermissions.includes('*')
        );
        
        if (hasPermission) {
            return next();
        }
        
        res.status(403).json({ 
            error: 'Insufficient permissions', 
            protocol: 'x402',
            required: permissions
        });
    };
};

// Audit Middleware
const auditMiddleware = (action, resource) => {
    return async (req, res, next) => {
        const originalSend = res.send;
        const startTime = Date.now();
        
        res.send = function(data) {
            const duration = Date.now() - startTime;
            
            AuditLog.create({
                action,
                resource,
                resourceId: req.params.id || req.body?.id,
                userId: req.admin?.id,
                username: req.admin?.username,
                userIp: req.ip,
                userAgent: req.get('User-Agent'),
                details: {
                    method: req.method,
                    url: req.url,
                    params: req.params,
                    query: req.query,
                    body: req.body,
                    statusCode: res.statusCode
                },
                status: res.statusCode < 400 ? 'success' : 'failure',
                errorMessage: res.statusCode >= 400 ? data : null,
                duration
            }).catch(err => logger.error('Audit log error:', err));
            
            originalSend.call(this, data);
        };
        
        next();
    };
};

// Input Validation Middleware
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                protocol: 'x402',
                details: errors.array()
            });
        }
        
        next();
    };
};

// ==================== STARKNET CLIENT ====================

let provider, account, x402Contract;
let currentRpcIndex = 0;

const ERC20_ABI = [
    {
        name: 'transfer',
        type: 'function',
        inputs: [
            { name: 'recipient', type: 'felt' },
            { name: 'amount', type: 'Uint256' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'transferFrom',
        type: 'function',
        inputs: [
            { name: 'sender', type: 'felt' },
            { name: 'recipient', type: 'felt' },
            { name: 'amount', type: 'Uint256' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'balanceOf',
        type: 'function',
        inputs: [{ name: 'account', type: 'felt' }],
        outputs: [{ name: 'balance', type: 'Uint256' }],
        stateMutability: 'view'
    },
    {
        name: 'approve',
        type: 'function',
        inputs: [
            { name: 'spender', type: 'felt' },
            { name: 'amount', type: 'Uint256' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'allowance',
        type: 'function',
        inputs: [
            { name: 'owner', type: 'felt' },
            { name: 'spender', type: 'felt' }
        ],
        outputs: [{ name: 'remaining', type: 'Uint256' }],
        stateMutability: 'view'
    }
];

const X402_CONTRACT_ABI = [
    {
        name: 'create_payment_request',
        type: 'function',
        inputs: [
            { name: 'amount', type: 'Uint256' },
            { name: 'token', type: 'felt' },
            { name: 'resource', type: 'felt' },
            { name: 'client_id', type: 'felt' }
        ],
        outputs: [{ name: 'payment_id', type: 'felt' }]
    },
    {
        name: 'process_immediate_payment',
        type: 'function',
        inputs: [
            { name: 'payment_id', type: 'felt' },
            { name: 'token', type: 'felt' },
            { name: 'amount', type: 'Uint256' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'verify_payment',
        type: 'function',
        inputs: [
            { name: 'payment_id', type: 'felt' },
            { name: 'payer', type: 'felt' }
        ],
        outputs: [{ name: 'verified', type: 'felt' }],
        stateMutability: 'view'
    },
    {
        name: 'authorize_deferred_payment',
        type: 'function',
        inputs: [
            { name: 'client_id', type: 'felt' },
            { name: 'amount', type: 'Uint256' },
            { name: 'resource', type: 'felt' }
        ],
        outputs: [
            { name: 'authorization', type: 'felt' },
            { name: 'signature', type: 'felt' }
        ]
    },
    {
        name: 'commit_deferred_payment',
        type: 'function',
        inputs: [
            { name: 'client_id', type: 'felt' },
            { name: 'amount', type: 'Uint256' },
            { name: 'resource', type: 'felt' },
            { name: 'authorization', type: 'felt' },
            { name: 'signature', type: 'felt' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'settle_deferred_payments',
        type: 'function',
        inputs: [
            { name: 'client_id', type: 'felt' },
            { name: 'token', type: 'felt' }
        ],
        outputs: [{ name: 'success', type: 'felt' }]
    },
    {
        name: 'get_deferred_balance',
        type: 'function',
        inputs: [{ name: 'client_id', type: 'felt' }],
        outputs: [{ name: 'balance', type: 'Uint256' }],
        stateMutability: 'view'
    },
    {
        name: 'get_payment_details',
        type: 'function',
        inputs: [{ name: 'payment_id', type: 'felt' }],
        outputs: [{ name: 'details', type: 'PaymentDetails' }],
        stateMutability: 'view'
    }
];

// Initialize Starknet with Fallback Support
async function initializeStarknet() {
    try {
        const rpcs = [CONFIG.STARKNET_RPC_URL, ...CONFIG.STARKNET_FALLBACK_RPCS];
        
        for (let i = 0; i < rpcs.length; i++) {
            try {
                provider = new RpcProvider({ nodeUrl: rpcs[i] });
                await provider.getChainId(); // Test connection
                
                currentRpcIndex = i;
                logger.info(`Starknet provider initialized: ${rpcs[i]}`);
                break;
            } catch (error) {
                logger.warn(`Failed to connect to RPC ${rpcs[i]}:`, error.message);
                if (i === rpcs.length - 1) {
                    throw new Error('All RPC endpoints failed');
                }
            }
        }
        
        // Initialize account if credentials provided
        if (CONFIG.TREASURY_PRIVATE_KEY && CONFIG.TREASURY_ADDRESS) {
            account = new Account(provider, CONFIG.TREASURY_ADDRESS, CONFIG.TREASURY_PRIVATE_KEY);
            logger.info('Treasury account initialized:', CONFIG.TREASURY_ADDRESS);
        } else {
            logger.warn('Treasury account not configured - read-only mode');
        }
        
        // Initialize X402 contract
        if (CONFIG.X402_CONTRACT_ADDRESS) {
            x402Contract = new Contract(X402_CONTRACT_ABI, CONFIG.X402_CONTRACT_ADDRESS, provider);
            if (account) {
                x402Contract.connect(account);
            }
            logger.info('X402 contract initialized:', CONFIG.X402_CONTRACT_ADDRESS);
            
            // Verify contract is accessible
            const isPaused = await x402Contract.is_paused();
            logger.info('Contract status - paused:', isPaused);
        } else {
            logger.error('X402 contract address not configured');
            throw new Error('X402 contract address required');
        }
        
        return true;
    } catch (error) {
        logger.error('Starknet initialization error:', error);
        return false;
    }
}

// Retry wrapper for contract calls
async function retryContractCall(fn, maxRetries = CONFIG.MAX_RETRY_ATTEMPTS) {
    let lastError;
    
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            logger.warn(`Contract call attempt ${i + 1} failed:`, error.message);
            
            if (i < maxRetries - 1) {
                await new Promise(resolve => 
                    setTimeout(resolve, CONFIG.RETRY_DELAY * (i + 1))
                );
            }
        }
    }
    
    throw lastError;
}

// ==================== UTILITY FUNCTIONS ====================

function stringToFelt(str) {
    if (!str) return '0x0';
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let result = '0x';
    for (let i = 0; i < Math.min(bytes.length, 31); i++) {
        result += bytes[i].toString(16).padStart(2, '0');
    }
    return result;
}

function feltToString(felt) {
    try {
        const hex = felt.toString(16).replace('0x', '');
        if (!hex) return '';
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return new TextDecoder().decode(new Uint8Array(bytes)).replace(/\0/g, '');
    } catch (error) {
        logger.error('Felt to string conversion error:', error);
        return '';
    }
}

function parseUint256(uint256) {
    if (!uint256) return 0n;
    if (typeof uint256 === 'bigint') return uint256;
    if (typeof uint256 === 'string') return BigInt(uint256);
    
    const low = BigInt(uint256.low || 0);
    const high = BigInt(uint256.high || 0);
    return low + (high << 128n);
}

function toUint256(value) {
    const bn = BigInt(value);
    return {
        low: (bn & ((1n << 128n) - 1n)).toString(),
        high: (bn >> 128n).toString()
    };
}

function getTokenInfo(tokenAddressOrSymbol) {
    // Try to find by symbol first
    const bySymbol = Object.values(SUPPORTED_TOKENS).find(
        t => t.symbol === tokenAddressOrSymbol
    );
    if (bySymbol) return bySymbol;
    
    // Try to find by address
    const byAddress = Object.values(SUPPORTED_TOKENS).find(
        t => t.address.toLowerCase() === tokenAddressOrSymbol.toLowerCase()
    );
    if (byAddress) return byAddress;
    
    return null;
}

function formatTokenAmount(amount, tokenSymbol) {
    const token = getTokenInfo(tokenSymbol);
    if (!token) return amount;
    
    const divisor = BigInt(10) ** BigInt(token.decimals);
    const integerPart = BigInt(amount) / divisor;
    const fractionalPart = BigInt(amount) % divisor;
    
    return `${integerPart}.${fractionalPart.toString().padStart(token.decimals, '0')}`;
}

async function getTokenBalance(tokenAddress, accountAddress) {
    const cacheKey = `token_balance:${tokenAddress}:${accountAddress}`;
    const cached = await cache.get(cacheKey);
    if (cached !== null) return cached;

    try {
        const balance = await retryContractCall(async () => {
            const contract = new Contract(ERC20_ABI, tokenAddress, provider);
            const result = await contract.balanceOf(accountAddress);
            return parseUint256(result).toString();
        });
        
        await cache.set(cacheKey, balance, 60);
        return balance;
    } catch (error) {
        logger.error('Get token balance error:', { 
            tokenAddress, 
            accountAddress, 
            error: error.message 
        });
        return '0';
    }
}

async function verifyOnChainPayment(paymentId, payer) {
    const cacheKey = `payment_verification:${paymentId}:${payer}`;
    const cached = await cache.get(cacheKey);
    if (cached !== null) return cached;

    try {
        const verified = await retryContractCall(async () => {
            const result = await x402Contract.verify_payment(paymentId, payer);
            return result === 1n || result === '1' || result === true;
        });
        
        await cache.set(cacheKey, verified, 300);
        return verified;
    } catch (error) {
        logger.error('On-chain verification error:', { 
            paymentId, 
            payer, 
            error: error.message 
        });
        return false;
    }
}

async function getPaymentDetailsFromContract(paymentId) {
    const cacheKey = `payment_details:${paymentId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;

    try {
        const details = await retryContractCall(async () => {
            const result = await x402Contract.get_payment_details(paymentId);
            return {
                payment_id: result.payment_id,
                payer: result.payer,
                amount: parseUint256(result.amount).toString(),
                token: result.token,
                status: Number(result.status),
                payment_type: Number(result.payment_type),
                resource: result.resource,
                client_id: result.client_id,
                timestamp: Number(result.timestamp),
                confirmed_at: Number(result.confirmed_at),
                block_number: Number(result.block_number)
            };
        });
        
        await cache.set(cacheKey, details, 300);
        return details;
    } catch (error) {
        logger.error('Get payment details error:', { 
            paymentId, 
            error: error.message 
        });
        return null;
    }
}

// Generate secure payment authorization
function generatePaymentAuthorization(clientId, amount, resource, timestamp) {
    const data = `${clientId}:${amount}:${resource}:${timestamp}:${CONFIG.CONTRACT_SECRET_KEY}`;
    return crypto.createHash('sha256').update(data).digest('hex');
}

function verifyPaymentAuthorization(clientId, amount, resource, timestamp, authorization) {
    const expected = generatePaymentAuthorization(clientId, amount, resource, timestamp);
    return crypto.timingSafeEqual(
        Buffer.from(expected),
        Buffer.from(authorization)
    );
}

// ==================== TOKEN PRICE FEEDS ====================

async function getTokenPrices() {
    const cacheKey = 'token_prices';
    const cached = await cache.get(cacheKey);
    if (cached) return cached;

    try {
        const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
            params: {
                ids: 'usd-coin,ethereum,starknet,tether,dai',
                vs_currencies: 'usd',
                include_24hr_change: true
            },
            timeout: 5000
        });

        const prices = {
            USDC: {
                usd: response.data['usd-coin']?.usd || 1.0,
                change24h: response.data['usd-coin']?.usd_24h_change || 0
            },
            ETH: {
                usd: response.data['ethereum']?.usd || 3000,
                change24h: response.data['ethereum']?.usd_24h_change || 0
            },
            STRK: {
                usd: response.data['starknet']?.usd || 0.5,
                change24h: response.data['starknet']?.usd_24h_change || 0
            },
            USDT: {
                usd: response.data['tether']?.usd || 1.0,
                change24h: response.data['tether']?.usd_24h_change || 0
            },
            DAI: {
                usd: response.data['dai']?.usd || 1.0,
                change24h: response.data['dai']?.usd_24h_change || 0
            }
        };

        await cache.set(cacheKey, prices, 300);
        return prices;
    } catch (error) {
        logger.error('Price feed error:', error);
        return {
            USDC: { usd: 1.0, change24h: 0 },
            ETH: { usd: 3000, change24h: 0 },
            STRK: { usd: 0.5, change24h: 0 },
            USDT: { usd: 1.0, change24h: 0 },
            DAI: { usd: 1.0, change24h: 0 }
        };
    }
}

// ==================== METRICS ====================

async function recordMetric(name, value, labels = {}) {
    if (!CONFIG.ENABLE_METRICS) return;
    
    try {
        await Metric.create({
            name,
            value,
            labels,
            timestamp: new Date()
        });
        
        // Also cache recent metrics
        const cacheKey = `metric:${name}:latest`;
        await cache.set(cacheKey, { value, labels, timestamp: Date.now() }, 3600);
    } catch (error) {
        logger.error('Record metric error:', error);
    }
}

async function getMetrics(name, startTime, endTime) {
    try {
        const where = { name };
        
        if (startTime || endTime) {
            where.timestamp = {};
            if (startTime) where.timestamp[Op.gte] = new Date(startTime);
            if (endTime) where.timestamp[Op.lte] = new Date(endTime);
        }
        
        const metrics = await Metric.findAll({
            where,
            order: [['timestamp', 'DESC']],
            limit: 1000
        });
        
        return metrics;
    } catch (error) {
        logger.error('Get metrics error:', error);
        return [];
    }
}

// ==================== WEBHOOK DELIVERY ====================

async function sendWebhook(clientId, event, payload) {
    if (!CONFIG.ENABLE_WEBHOOKS) return;
    
    try {
        const client = await Client.findOne({ where: { clientId } });
        if (!client || !client.webhookUrl) {
            return;
        }
        
        const webhook = await WebhookDelivery.create({
            clientId,
            webhookUrl: client.webhookUrl,
            event,
            payload,
            status: 'pending'
        });
        
        await deliverWebhook(webhook, client.webhookSecret);
    } catch (error) {
        logger.error('Send webhook error:', error);
    }
}

async function deliverWebhook(webhook, secret) {
    try {
        const signature = crypto
            .createHmac('sha256', secret || CONFIG.WEBHOOK_SECRET)
            .update(JSON.stringify(webhook.payload))
            .digest('hex');
        
        const response = await axios.post(webhook.webhookUrl, webhook.payload, {
            headers: {
                'Content-Type': 'application/json',
                'X-Webhook-Signature': signature,
                'X-Webhook-Event': webhook.event,
                'X-Webhook-ID': webhook.id
            },
            timeout: CONFIG.WEBHOOK_TIMEOUT
        });
        
        await webhook.update({
            status: 'delivered',
            responseStatus: response.status,
            responseBody: JSON.stringify(response.data),
            deliveredAt: new Date()
        });
        
        logger.info('Webhook delivered', { 
            webhookId: webhook.id, 
            event: webhook.event 
        });
    } catch (error) {
        const attempts = webhook.attempts + 1;
        const maxAttempts = CONFIG.WEBHOOK_RETRY_ATTEMPTS;
        
        if (attempts < maxAttempts) {
            const nextRetryAt = new Date(Date.now() + (attempts * 60000)); // Exponential backoff
            
            await webhook.update({
                status: 'pending',
                attempts,
                errorMessage: error.message,
                nextRetryAt
            });
        } else {
            await webhook.update({
                status: 'failed',
                attempts,
                errorMessage: error.message
            });
        }
        
        logger.error('Webhook delivery error:', {
            webhookId: webhook.id,
            attempts,
            error: error.message
        });
    }
}

// ==================== EVENT MONITORING ====================

let lastProcessedBlock = 0;
let isMonitoring = false;

async function startEventMonitoring() {
    if (isMonitoring) {
        logger.warn('Event monitoring already running');
        return;
    }
    
    isMonitoring = true;
    logger.info('Starting event monitoring');
    
    // Load last processed block from cache
    const cached = await cache.get('last_processed_block');
    if (cached) {
        lastProcessedBlock = parseInt(cached);
    }
    
    while (isMonitoring) {
        try {
            await monitorContractEvents();
            await new Promise(resolve => setTimeout(resolve, CONFIG.BLOCK_POLL_INTERVAL));
        } catch (error) {
            logger.error('Event monitoring cycle error:', error);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
}

async function stopEventMonitoring() {
    isMonitoring = false;
    logger.info('Stopping event monitoring');
}

async function monitorContractEvents() {
    try {
        const currentBlock = await provider.getBlockNumber();
        
        if (lastProcessedBlock === 0) {
            lastProcessedBlock = currentBlock - 100; // Start from 100 blocks ago
        }
        
        if (currentBlock <= lastProcessedBlock) {
            return;
        }
        
        logger.debug(`Monitoring events from block ${lastProcessedBlock + 1} to ${currentBlock}`);
        
        // Process blocks in batches
        const batchSize = 10;
        for (let blockNum = lastProcessedBlock + 1; blockNum <= currentBlock; blockNum += batchSize) {
            const endBlock = Math.min(blockNum + batchSize - 1, currentBlock);
            
            await processBlockRange(blockNum, endBlock);
        }
        
        lastProcessedBlock = currentBlock;
        await cache.set('last_processed_block', currentBlock.toString(), 86400);
        
        // Record metrics
        await recordMetric('blocks_processed', currentBlock - lastProcessedBlock);
        
    } catch (error) {
        logger.error('Event monitoring error:', error);
    }
}

async function processBlockRange(startBlock, endBlock) {
    try {
        for (let blockNum = startBlock; blockNum <= endBlock; blockNum++) {
            try {
                const block = await provider.getBlock(blockNum);
                
                if (block && block.transactions) {
                    for (const txHash of block.transactions) {
                        await processTransaction(txHash, blockNum);
                    }
                }
            } catch (error) {
                logger.error(`Error processing block ${blockNum}:`, error);
            }
        }
    } catch (error) {
        logger.error('Process block range error:', error);
    }
}

async function processTransaction(txHash, blockNumber) {
    try {
        const receipt = await provider.getTransactionReceipt(txHash);
        
        if (receipt && receipt.events) {
            for (const event of receipt.events) {
                if (event.from_address === CONFIG.X402_CONTRACT_ADDRESS) {
                    await processContractEvent(event, blockNumber, txHash);
                }
            }
        }
    } catch (error) {
        logger.error(`Error processing transaction ${txHash}:`, error);
    }
}

async function processContractEvent(event, blockNumber, txHash) {
    try {
        const eventKey = event.keys[0];
        let eventName = 'Unknown';
        let eventData = {};

        // PaymentCreated Event
        if (eventKey === hash.getSelectorFromName('PaymentCreated')) {
            eventName = 'PaymentCreated';
            eventData = {
                payment_id: event.keys[1],
                payer: event.keys[2],
                amount: event.data[0],
                token: event.data[1],
                resource: event.data[2],
                client_id: event.data[3],
                timestamp: event.data[4]
            };
            
            const tokenInfo = getTokenInfo(eventData.token);
            
            await Payment.create({
                paymentId: eventData.payment_id,
                clientId: feltToString(eventData.client_id),
                payer: eventData.payer,
                amount: eventData.amount,
                token: eventData.token,
                tokenSymbol: tokenInfo?.symbol,
                status: 'pending',
                paymentType: 'immediate',
                resource: feltToString(eventData.resource),
                blockNumber: blockNumber,
                txHash: txHash,
                metadata: { eventData }
            });
            
            await sendWebhook(feltToString(eventData.client_id), 'payment.created', {
                paymentId: eventData.payment_id,
                amount: eventData.amount,
                token: tokenInfo?.symbol,
                payer: eventData.payer,
                blockNumber,
                txHash
            });
            
        // PaymentConfirmed Event
        } else if (eventKey === hash.getSelectorFromName('PaymentConfirmed')) {
            eventName = 'PaymentConfirmed';
            eventData = {
                payment_id: event.keys[1],
                payer: event.data[0],
                amount: event.data[1],
                block_number: event.data[2]
            };
            
            const payment = await Payment.findOne({ 
                where: { paymentId: eventData.payment_id } 
            });
            
            if (payment) {
                await payment.update({
                    status: 'confirmed',
                    confirmedAt: new Date(),
                    blockNumber: eventData.block_number,
                    txHash: txHash,
                    confirmations: CONFIG.PAYMENT_CONFIRMATION_BLOCKS
                });
                
                await sendWebhook(payment.clientId, 'payment.confirmed', {
                    paymentId: eventData.payment_id,
                    amount: eventData.amount,
                    payer: eventData.payer,
                    blockNumber: eventData.block_number,
                    txHash
                });
            }
            
        // DeferredPaymentAuthorized Event
        } else if (eventKey === hash.getSelectorFromName('DeferredPaymentAuthorized')) {
            eventName = 'DeferredPaymentAuthorized';
            eventData = {
                client_id: event.keys[1],
                amount: event.data[0],
                authorization: event.data[1],
                timestamp: event.data[2]
            };
            
            const clientId = feltToString(eventData.client_id);
            
            await DeferredPayment.create({
                clientId,
                amount: eventData.amount,
                authorization: eventData.authorization,
                signature: '0x0', // Will be updated when committed
                timestamp: eventData.timestamp,
                settled: false
            });
            
            await sendWebhook(clientId, 'deferred.authorized', {
                authorization: eventData.authorization,
                amount: eventData.amount,
                timestamp: eventData.timestamp
            });
            
        // DeferredPaymentsSettled Event
        } else if (eventKey === hash.getSelectorFromName('DeferredPaymentsSettled')) {
            eventName = 'DeferredPaymentsSettled';
            eventData = {
                client_id: event.keys[1],
                total_amount: event.data[0],
                token: event.data[1],
                payment_count: event.data[2]
            };
            
            const clientId = feltToString(eventData.client_id);
            
            await DeferredPayment.update(
                { 
                    settled: true, 
                    settlementTx: txHash,
                    settledAt: new Date()
                },
                { where: { clientId, settled: false } }
            );
            
            await sendWebhook(clientId, 'deferred.settled', {
                totalAmount: eventData.total_amount,
                token: eventData.token,
                paymentCount: eventData.payment_count,
                txHash,
                blockNumber
            });
        }
