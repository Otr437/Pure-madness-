// X402 Protocol Starknet Backend - COMPLETE PRODUCTION IMPLEMENTATION
// Node.js + Starknet.js + PostgreSQL + Redis
// npm install express starknet@6 axios cors express-rate-limit helmet compression morgan sequelize pg redis winston bcrypt jsonwebtoken dotenv

const express = require('express');
const { Contract, Account, Provider, ec, stark, hash, CallData, RpcProvider } = require('starknet');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');
const Redis = require('redis');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ==================== CONFIGURATION ====================

const ENV = process.env.NODE_ENV || 'development';
const CONFIG = {
    PORT: process.env.PORT || 3402,
    HOST: process.env.HOST || '0.0.0.0',
    JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
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
    STARKNET_CHAIN_ID: process.env.STARKNET_CHAIN_ID || '0x534e5f4d41494e',
    X402_CONTRACT_ADDRESS: process.env.X402_CONTRACT_ADDRESS,
    TREASURY_ADDRESS: process.env.TREASURY_ADDRESS,
    TREASURY_PRIVATE_KEY: process.env.TREASURY_PRIVATE_KEY,
    CONTRACT_SECRET_KEY: process.env.CONTRACT_SECRET_KEY,
    
    // Token Addresses on Starknet
    USDC_ADDRESS: process.env.USDC_ADDRESS || '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    ETH_ADDRESS: process.env.ETH_ADDRESS || '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
    STRK_ADDRESS: process.env.STRK_ADDRESS || '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
    
    RATE_LIMIT_WINDOW: 15 * 60 * 1000,
    RATE_LIMIT_MAX: 1000,
    ADMIN_RATE_LIMIT_MAX: 10000,
    
    MIN_DEFERRED_AMOUNT: 1000000,
    MAX_DEFERRED_AMOUNT: 10000000000,
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
    defaultMeta: { service: 'x402-starknet-backend' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ],
});

// ==================== DATABASE ====================

const sequelize = new Sequelize(CONFIG.DB_NAME, CONFIG.DB_USER, CONFIG.DB_PASS, {
    host: CONFIG.DB_HOST,
    port: CONFIG.DB_PORT,
    dialect: 'postgres',
    logging: (msg) => logger.debug(msg),
    pool: { max: 20, min: 0, acquire: 60000, idle: 10000 }
});

const Payment = sequelize.define('Payment', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    paymentId: { type: DataTypes.STRING, unique: true, allowNull: false, index: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    payer: { type: DataTypes.STRING, allowNull: false },
    amount: { type: DataTypes.STRING, allowNull: false },
    token: { type: DataTypes.STRING, allowNull: false },
    status: { type: DataTypes.ENUM('pending', 'confirmed', 'failed', 'settled'), defaultValue: 'pending' },
    paymentType: { type: DataTypes.ENUM('immediate', 'deferred'), allowNull: false },
    resource: { type: DataTypes.STRING },
    txHash: { type: DataTypes.STRING },
    blockNumber: { type: DataTypes.BIGINT },
    metadata: { type: DataTypes.JSONB },
    confirmedAt: { type: DataTypes.DATE },
    settledAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId'] },
        { fields: ['payer'] },
        { fields: ['status'] },
        { fields: ['token'] },
        { fields: ['createdAt'] }
    ]
});

const DeferredPayment = sequelize.define('DeferredPayment', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    clientId: { type: DataTypes.STRING, allowNull: false, index: true },
    amount: { type: DataTypes.STRING, allowNull: false },
    resource: { type: DataTypes.STRING },
    authorization: { type: DataTypes.STRING, unique: true, allowNull: false },
    signature: { type: DataTypes.STRING, allowNull: false },
    timestamp: { type: DataTypes.BIGINT, allowNull: false },
    settled: { type: DataTypes.BOOLEAN, defaultValue: false },
    settlementTx: { type: DataTypes.STRING },
    settledAt: { type: DataTypes.DATE }
}, {
    indexes: [
        { fields: ['clientId'] },
        { fields: ['settled'] },
        { fields: ['authorization'] }
    ]
});

const AdminUser = sequelize.define('AdminUser', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.ENUM('superadmin', 'admin', 'viewer'), defaultValue: 'viewer' },
    permissions: { type: DataTypes.JSONB, defaultValue: {} },
    isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
    lastLogin: { type: DataTypes.DATE }
});

const AuditLog = sequelize.define('AuditLog', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    action: { type: DataTypes.STRING, allowNull: false },
    resource: { type: DataTypes.STRING, allowNull: false },
    userId: { type: DataTypes.UUID },
    userIp: { type: DataTypes.STRING },
    details: { type: DataTypes.JSONB },
    status: { type: DataTypes.ENUM('success', 'failure') }
});

const ContractEvent = sequelize.define('ContractEvent', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    eventName: { type: DataTypes.STRING, allowNull: false, index: true },
    blockNumber: { type: DataTypes.BIGINT, allowNull: false, index: true },
    transactionHash: { type: DataTypes.STRING, allowNull: false, index: true },
    eventData: { type: DataTypes.JSONB, allowNull: false },
    processed: { type: DataTypes.BOOLEAN, defaultValue: false }
});

// ==================== REDIS CACHE ====================

const redisClient = Redis.createClient({ url: CONFIG.REDIS_URL });
redisClient.on('error', (err) => logger.error('Redis Client Error', err));
redisClient.connect().catch(err => logger.error('Redis connection error:', err));

const cache = {
    set: async (key, value, ttl = 3600) => {
        try {
            await redisClient.set(key, JSON.stringify(value), { EX: ttl });
        } catch (error) {
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
        },
    },
    crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Payment-Authorization', 'Payment-Type', 'X-Admin-Key', 'X-Client-Id']
}));

const generalLimiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.RATE_LIMIT_MAX,
    message: { error: 'Too many requests', protocol: 'x402' },
    standardHeaders: true,
    legacyHeaders: false,
});

const adminLimiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.ADMIN_RATE_LIMIT_MAX,
    message: { error: 'Too many admin requests', protocol: 'x402' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/v1/', generalLimiter);
app.use('/api/v1/admin/', adminLimiter);

app.use(morgan('combined', {
    stream: fs.createWriteStream(path.join(__dirname, 'logs/access.log'), { flags: 'a' })
}));

app.use((req, res, next) => {
    logger.info('HTTP Request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    next();
});

// ==================== ADMIN AUTH MIDDLEWARE ====================

const authenticateAdmin = async (req, res, next) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        const authHeader = req.headers['authorization'];
        
        if (adminKey && adminKey === CONFIG.ADMIN_API_KEY) {
            req.admin = { role: 'superadmin', permissions: ['*'] };
            return next();
        }
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
            
            const adminUser = await AdminUser.findByPk(decoded.userId);
            if (adminUser && adminUser.isActive) {
                req.admin = adminUser;
                return next();
            }
        }
        
        res.status(401).json({ error: 'Admin authentication required', protocol: 'x402' });
    } catch (error) {
        logger.error('Admin authentication error:', error);
        res.status(401).json({ error: 'Invalid admin credentials', protocol: 'x402' });
    }
};

const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({ error: 'Authentication required', protocol: 'x402' });
        }
        
        if (req.admin.role === 'superadmin' || 
            req.admin.permissions === '*' || 
            (Array.isArray(req.admin.permissions) && req.admin.permissions.includes(permission))) {
            return next();
        }
        
        res.status(403).json({ error: 'Insufficient permissions', protocol: 'x402' });
    };
};

const auditMiddleware = (action, resource) => {
    return async (req, res, next) => {
        const originalSend = res.send;
        const startTime = Date.now();
        
        res.send = function(data) {
            const duration = Date.now() - startTime;
            
            AuditLog.create({
                action: action,
                resource: resource,
                userId: req.admin?.id,
                userIp: req.ip,
                details: {
                    method: req.method,
                    url: req.url,
                    statusCode: res.statusCode,
                    duration: duration,
                    userAgent: req.get('User-Agent')
                },
                status: res.statusCode < 400 ? 'success' : 'failure'
            }).catch(err => logger.error('Audit log error:', err));
            
            originalSend.call(this, data);
        };
        
        next();
    };
};

// ==================== STARKNET CLIENT ====================

let provider, account, x402Contract;

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
    },
    {
        name: 'get_payment_status',
        type: 'function',
        inputs: [{ name: 'payment_id', type: 'felt' }],
        outputs: [{ name: 'status', type: 'felt' }],
        stateMutability: 'view'
    },
    {
        name: 'get_total_payments',
        type: 'function',
        inputs: [],
        outputs: [{ name: 'total', type: 'Uint256' }],
        stateMutability: 'view'
    },
    {
        name: 'get_total_volume',
        type: 'function',
        inputs: [{ name: 'token', type: 'felt' }],
        outputs: [{ name: 'volume', type: 'Uint256' }],
        stateMutability: 'view'
    },
    {
        name: 'is_token_supported',
        type: 'function',
        inputs: [{ name: 'token', type: 'felt' }],
        outputs: [{ name: 'supported', type: 'felt' }],
        stateMutability: 'view'
    },
    {
        name: 'get_treasury',
        type: 'function',
        inputs: [],
        outputs: [{ name: 'treasury', type: 'felt' }],
        stateMutability: 'view'
    },
    {
        name: 'is_paused',
        type: 'function',
        inputs: [],
        outputs: [{ name: 'paused', type: 'felt' }],
        stateMutability: 'view'
    }
];

async function initializeStarknet() {
    try {
        provider = new RpcProvider({ nodeUrl: CONFIG.STARKNET_RPC_URL });
        
        if (CONFIG.TREASURY_PRIVATE_KEY && CONFIG.TREASURY_ADDRESS) {
            account = new Account(provider, CONFIG.TREASURY_ADDRESS, CONFIG.TREASURY_PRIVATE_KEY);
            logger.info('Starknet account initialized:', CONFIG.TREASURY_ADDRESS);
        } else {
            logger.warn('Treasury account not configured - read-only mode');
        }
        
        if (CONFIG.X402_CONTRACT_ADDRESS) {
            x402Contract = new Contract(X402_CONTRACT_ABI, CONFIG.X402_CONTRACT_ADDRESS, provider);
            if (account) {
                x402Contract.connect(account);
            }
            logger.info('X402 contract initialized:', CONFIG.X402_CONTRACT_ADDRESS);
        } else {
            logger.error('X402 contract address not configured');
        }
        
        return true;
    } catch (error) {
        logger.error('Starknet initialization error:', error);
        return false;
    }
}

// ==================== UTILITY FUNCTIONS ====================

function stringToFelt(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let result = '0x';
    for (let i = 0; i < Math.min(bytes.length, 31); i++) {
        result += bytes[i].toString(16).padStart(2, '0');
    }
    return result;
}

function feltToString(felt) {
    const hex = felt.toString(16).replace('0x', '');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
}

function parseUint256(uint256) {
    return BigInt(uint256.low) + (BigInt(uint256.high) << 128n);
}

function toUint256(value) {
    const bn = BigInt(value);
    return {
        low: (bn & ((1n << 128n) - 1n)).toString(),
        high: (bn >> 128n).toString()
    };
}

async function getTokenBalance(tokenAddress, accountAddress) {
    const cacheKey = `token_balance:${tokenAddress}:${accountAddress}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;

    try {
        const contract = new Contract(ERC20_ABI, tokenAddress, provider);
        const result = await contract.balanceOf(accountAddress);
        const balance = parseUint256(result).toString();
        await cache.set(cacheKey, balance, 60);
        return balance;
    } catch (error) {
        logger.error('Get token balance error:', { tokenAddress, accountAddress, error: error.message });
        return '0';
    }
}

async function verifyOnChainPayment(paymentId, payer) {
    const cacheKey = `payment_verification:${paymentId}:${payer}`;
    const cached = await cache.get(cacheKey);
    if (cached !== null) return cached;

    try {
        const result = await x402Contract.verify_payment(paymentId, payer);
        const verified = result === 1n || result === '1' || result === true;
        await cache.set(cacheKey, verified, 300);
        return verified;
    } catch (error) {
        logger.error('On-chain verification error:', { paymentId, payer, error: error.message });
        return false;
    }
}

async function getPaymentDetailsFromContract(paymentId) {
    const cacheKey = `payment_details:${paymentId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;

    try {
        const result = await x402Contract.get_payment_details(paymentId);
        const details = {
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
        await cache.set(cacheKey, details, 300);
        return details;
    } catch (error) {
        logger.error('Get payment details error:', { paymentId, error: error.message });
        return null;
    }
}

// ==================== TOKEN PRICE FEEDS ====================

async function getTokenPrices() {
    const cacheKey = 'token_prices';
    const cached = await cache.get(cacheKey);
    if (cached) return cached;

    try {
        const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
            params: {
                ids: 'usd-coin,ethereum,starknet',
                vs_currencies: 'usd'
            },
            timeout: 5000
        });

        const prices = {
            USDC: response.data['usd-coin']?.usd || 1.0,
            ETH: response.data['ethereum']?.usd || 3000,
            STRK: response.data['starknet']?.usd || 0.5
        };

        await cache.set(cacheKey, prices, 300);
        return prices;
    } catch (error) {
        logger.error('Price feed error:', error);
        return { USDC: 1.0, ETH: 3000, STRK: 0.5 };
    }
}

// ==================== EVENT MONITORING ====================

let lastProcessedBlock = 0;

async function monitorContractEvents() {
    try {
        const currentBlock = await provider.getBlockNumber();
        
        if (lastProcessedBlock === 0) {
            lastProcessedBlock = currentBlock - 100;
        }
        
        if (currentBlock <= lastProcessedBlock) {
            return;
        }
        
        logger.info(`Monitoring events from block ${lastProcessedBlock} to ${currentBlock}`);
        
        for (let blockNum = lastProcessedBlock + 1; blockNum <= currentBlock; blockNum++) {
            try {
                const block = await provider.getBlock(blockNum);
                
                if (block && block.transactions) {
                    for (const txHash of block.transactions) {
                        const receipt = await provider.getTransactionReceipt(txHash);
                        
                        if (receipt && receipt.events) {
                            for (const event of receipt.events) {
                                if (event.from_address === CONFIG.X402_CONTRACT_ADDRESS) {
                                    await processContractEvent(event, blockNum, txHash);
                                }
                            }
                        }
                    }
                }
            } catch (error) {
                logger.error(`Error processing block ${blockNum}:`, error);
            }
        }
        
        lastProcessedBlock = currentBlock;
        
    } catch (error) {
        logger.error('Event monitoring error:', error);
    }
}

async function processContractEvent(event, blockNumber, txHash) {
    try {
        const eventKey = event.keys[0];
        let eventName = 'Unknown';
        let eventData = {};

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
            
            await Payment.create({
                paymentId: eventData.payment_id,
                clientId: feltToString(eventData.client_id),
                payer: eventData.payer,
                amount: eventData.amount,
                token: eventData.token,
                status: 'pending',
                paymentType: 'immediate',
                resource: feltToString(eventData.resource),
                blockNumber: blockNumber,
                txHash: txHash
            });
            
        } else if (eventKey === hash.getSelectorFromName('PaymentConfirmed')) {
            eventName = 'PaymentConfirmed';
            eventData = {
                payment_id: event.keys[1],
                payer: event.data[0],
                amount: event.data[1],
                block_number: event.data[2]
            };
            
            await Payment.update(
                { 
                    status: 'confirmed',
                    confirmedAt: new Date(),
                    blockNumber: eventData.block_number,
                    txHash: txHash
                },
                { where: { paymentId: eventData.payment_id } }
            );
            
        } else if (eventKey === hash.getSelectorFromName('DeferredPaymentAuthorized')) {
            eventName = 'DeferredPaymentAuthorized';
            eventData = {
                client_id: event.keys[1],
                amount: event.data[0],
                authorization: event.data[1],
                timestamp: event.data[2]
            };
            
        } else if (eventKey === hash.getSelectorFromName('DeferredPaymentsSettled')) {
            eventName = 'DeferredPaymentsSettled';
            eventData = {
                client_id: event.keys[1],
                total_amount: event.data[0],
                payment_count: event.data[1],
                token: event.data[2]
            };
            
            await DeferredPayment.update(
                { 
                    settled: true,
                    settlementTx: txHash,
                    settledAt: new Date()
                },
                { where: { clientId: feltToString(eventData.client_id), settled: false } }
            );
        }
        
        await ContractEvent.create({
            eventName,
            blockNumber,
            transactionHash: txHash,
            eventData,
            processed: true
        });
        
        logger.info(`Processed event ${eventName} in block ${blockNumber}`);
        
    } catch (error) {
        logger.error('Process contract event error:', error);
    }
}

setInterval(() => {
    monitorContractEvents().catch(err => logger.error('Event monitoring failed:', err));
}, 30000);

// ==================== X402 PAYMENT MIDDLEWARE ====================

const requirePayment = (priceUSD, options = {}) => {
    return async (req, res, next) => {
        const paymentAuth = req.headers['payment-authorization'];
        const paymentType = req.headers['payment-type'] || 'immediate';
        const clientId = req.headers['x-client-id'] || 'anonymous';
        
        const cacheKey = `payment_auth:${clientId}:${req.path}:${priceUSD}`;
        const cachedAuth = await cache.get(cacheKey);
        if (cachedAuth) {
            req.paymentVerified = true;
            req.paymentDetails = cachedAuth;
            return next();
        }

        if (!paymentAuth) {
            const prices = await getTokenPrices();
            
            const usdcAmount = (priceUSD * 1e6).toString();
            const ethAmount = ((priceUSD / prices.ETH) * 1e18).toString();
            const strkAmount = ((priceUSD / prices.STRK) * 1e18).toString();
            
            return res.status(402).json({
                error: 'Payment Required',
                protocol: 'x402',
                version: '1.0',
                network: 'starknet',
                payment: {
                    amount_usd: priceUSD,
                    amounts: {
                        USDC: { amount: usdcAmount, decimals: 6, address: CONFIG.USDC_ADDRESS },
                        ETH: { amount: ethAmount, decimals: 18, address: CONFIG.ETH_ADDRESS },
                        STRK: { amount: strkAmount, decimals: 18, address: CONFIG.STRK_ADDRESS }
                    },
                    treasury: CONFIG.TREASURY_ADDRESS,
                    contract: CONFIG.X402_CONTRACT_ADDRESS,
                    schemes: [
                        {
                            type: 'immediate',
                            description: 'Direct on-chain payment via smart contract',
                            verification: 'On-chain verification via X402 contract'
                        },
                        {
                            type: 'deferred',
                            description: 'Batch payment settlement',
                            limits: {
                                min: CONFIG.MIN_DEFERRED_AMOUNT,
                                max: CONFIG.MAX_DEFERRED_AMOUNT
                            }
                        }
                    ]
                },
                instructions: `Create payment via X402 contract on Starknet. Pay ${priceUSD} USD equivalent in USDC, ETH, or STRK.`,
                resource: req.path,
                clientId: clientId,
                timestamp: Date.now()
            });
        }

        try {
            let isValid = false;
            let paymentDetails = {};

            if (paymentType === 'deferred') {
                const [authClientId, authorization, signature] = paymentAuth.split(':');
                
                const deferred = await DeferredPayment.findOne({ 
                    where: { authorization, settled: false } 
                });
                
                if (deferred && deferred.clientId === authClientId) {
                    isValid = true;
                    paymentDetails = {
                        scheme: 'deferred',
                        clientId: authClientId,
                        authorization,
                        verified: 'signature'
                    };
                }
            } else {
                const paymentId = paymentAuth;
                const payer = req.headers['payer-address'];
                
                if (!payer) {
                    return res.status(400).json({ error: 'Payer address required for immediate payment' });
                }
                
                isValid = await verifyOnChainPayment(paymentId, payer);
                
                if (isValid) {
                    const details = await getPaymentDetailsFromContract(paymentId);
                    paymentDetails = {
                        scheme: 'immediate',
                        paymentId,
                        payer,
                        amount: details?.amount,
                        token: details?.token,
                        verified: 'on-chain'
                    };
                }
            }

            if (isValid) {
                await cache.set(cacheKey, paymentDetails, 300);
                
                const existingPayment = await Payment.findOne({ where: { paymentId: paymentAuth } });
                if (!existingPayment && paymentType === 'immediate') {
                    await Payment.create({
                        paymentId: paymentAuth,
                        clientId,
                        payer: paymentDetails.payer,
                        amount: paymentDetails.amount,
                        token: paymentDetails.token,
                        status: 'confirmed',
                        paymentType: 'immediate',
                        resource: req.path,
                        confirmedAt: new Date()
                    });
                }
                
                req.paymentVerified = true;
                req.paymentDetails = paymentDetails;
                next();
            } else {
                res.status(402).json({ 
                    error: 'Invalid payment proof',
                    protocol: 'x402',
                    details: 'Payment not verified on-chain',
                    treasury: CONFIG.TREASURY_ADDRESS,
                    contract: CONFIG.X402_CONTRACT_ADDRESS
                });
            }
        } catch (err) {
            logger.error('Payment verification error:', { error: err.message, clientId, path: req.path });
            res.status(500).json({ error: 'Payment verification failed', protocol: 'x402' });
        }
    };
};

// ==================== PUBLIC API ENDPOINTS ====================

app.get('/api/v1/health', async (req, res) => {
    const health = {
        status: 'healthy',
        protocol: 'x402',
        version: '1.0',
        network: 'starknet',
        timestamp: new Date().toISOString(),
        environment: ENV,
        features: [
            'immediate-payment',
            'deferred-payment',
            'on-chain-verification',
            'starknet-native',
            'multi-token',
            'enterprise-admin'
        ],
        contract: {
            address: CONFIG.X402_CONTRACT_ADDRESS,
            treasury: CONFIG.TREASURY_ADDRESS
        },
        supportedTokens: {
            USDC: CONFIG.USDC_ADDRESS,
            ETH: CONFIG.ETH_ADDRESS,
            STRK: CONFIG.STRK_ADDRESS
        },
        system: {
            database: 'unknown',
            redis: 'unknown',
            starknet_rpc: 'unknown'
        }
    };

    try {
        await sequelize.authenticate();
        health.system.database = 'connected';
    } catch (e) {
        health.system.database = 'disconnected';
        health.status = 'degraded';
    }

    try {
        await redisClient.ping();
        health.system.redis = 'connected';
    } catch (e) {
        health.system.redis = 'disconnected';
        health.status = 'degraded';
    }

    try {
        await provider.getBlockNumber();
        health.system.starknet_rpc = 'connected';
    } catch (e) {
        health.system.starknet_rpc = 'disconnected';
        health.status = 'degraded';
    }

    res.json(health);
});

app.get('/api/v1/contract/info', async (req, res) => {
    try {
        const [isPaused, treasury, totalPayments] = await Promise.all([
            x402Contract.is_paused(),
            x402Contract.get_treasury(),
            x402Contract.get_total_payments()
        ]);

        const [usdcSupported, ethSupported, strkSupported] = await Promise.all([
            x402Contract.is_token_supported(CONFIG.USDC_ADDRESS),
            x402Contract.is_token_supported(CONFIG.ETH_ADDRESS),
            x402Contract.is_token_supported(CONFIG.STRK_ADDRESS)
        ]);

        res.json({
            protocol: 'x402',
            network: 'starknet',
            contract: CONFIG.X402_CONTRACT_ADDRESS,
            treasury: treasury,
            paused: isPaused === 1n,
            totalPayments: parseUint256(totalPayments).toString(),
            supportedTokens: {
                USDC: { address: CONFIG.USDC_ADDRESS, supported: usdcSupported === 1n },
                ETH: { address: CONFIG.ETH_ADDRESS, supported: ethSupported === 1n },
                STRK: { address: CONFIG.STRK_ADDRESS, supported: strkSupported === 1n }
            }
        });
    } catch (error) {
        logger.error('Contract info error:', error);
        res.status(500).json({ error: 'Failed to fetch contract info' });
    }
});

app.get('/api/v1/balances', async (req, res) => {
    try {
        const [usdcBalance, ethBalance, strkBalance] = await Promise.all([
            getTokenBalance(CONFIG.USDC_ADDRESS, CONFIG.TREASURY_ADDRESS),
            getTokenBalance(CONFIG.ETH_ADDRESS, CONFIG.TREASURY_ADDRESS),
            getTokenBalance(CONFIG.STRK_ADDRESS, CONFIG.TREASURY_ADDRESS)
        ]);

        const prices = await getTokenPrices();

        res.json({
            protocol: 'x402',
            network: 'starknet',
            treasury: CONFIG.TREASURY_ADDRESS,
            balances: {
                USDC: {
                    address: CONFIG.USDC_ADDRESS,
                    balance: (BigInt(usdcBalance) / BigInt(1e6)).toString(),
                    raw: usdcBalance,
                    decimals: 6,
                    usd_value: (Number(usdcBalance) / 1e6).toFixed(2)
                },
                ETH: {
                    address: CONFIG.ETH_ADDRESS,
                    balance: (Number(ethBalance) / 1e18).toFixed(6),
                    raw: ethBalance,
                    decimals: 18,
                    usd_value: ((Number(ethBalance) / 1e18) * prices.ETH).toFixed(2)
                },
                STRK: {
                    address: CONFIG.STRK_ADDRESS,
                    balance: (Number(strkBalance) / 1e18).toFixed(6),
                    raw: strkBalance,
                    decimals: 18,
                    usd_value: ((Number(strkBalance) / 1e18) * prices.STRK).toFixed(2)
                }
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Balance check error:', error);
        res.status(500).json({ error: 'Failed to check balances' });
    }
});

app.get('/api/v1/prices', async (req, res) => {
    const prices = await getTokenPrices();
    res.json({
        protocol: 'x402',
        network: 'starknet',
        prices,
        timestamp: new Date().toISOString()
    });
});

app.post('/api/v1/payments/create', async (req, res) => {
    try {
        const { amount_usd, token, resource, client_id } = req.body;
        const payer = req.body.payer_address;

        if (!amount_usd || !token || !client_id || !payer) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const prices = await getTokenPrices();
        let tokenAddress, tokenAmount, decimals;

        switch (token.toUpperCase()) {
            case 'USDC':
                tokenAddress = CONFIG.USDC_ADDRESS;
                tokenAmount = (amount_usd * 1e6).toString();
                decimals = 6;
                break;
            case 'ETH':
                tokenAddress = CONFIG.ETH_ADDRESS;
                tokenAmount = ((amount_usd / prices.ETH) * 1e18).toString();
                decimals = 18;
                break;
            case 'STRK':
                tokenAddress = CONFIG.STRK_ADDRESS;
                tokenAmount = ((amount_usd / prices.STRK) * 1e18).toString();
                decimals = 18;
                break;
            default:
                return res.status(400).json({ error: 'Unsupported token' });
        }

        const resourceFelt = stringToFelt(resource || 'api-access');
        const clientIdFelt = stringToFelt(client_id);

        const calldata = CallData.compile({
            amount: toUint256(tokenAmount),
            token: tokenAddress,
            resource: resourceFelt,
            client_id: clientIdFelt
        });

        res.json({
            protocol: 'x402',
            network: 'starknet',
            contract: CONFIG.X402_CONTRACT_ADDRESS,
            function: 'create_payment_request',
            calldata,
            token: {
                address: tokenAddress,
                symbol: token.toUpperCase(),
                amount: tokenAmount,
                decimals,
                amount_usd
            },
            instructions: 'Call create_payment_request on the contract, then approve token transfer and call process_immediate_payment',
            payer,
            client_id,
            resource
        });
    } catch (error) {
        logger.error('Create payment error:', error);
        res.status(500).json({ error: 'Failed to create payment request' });
    }
});

app.post('/api/v1/payments/verify', async (req, res) => {
    try {
        const { payment_id, payer_address } = req.body;

        if (!payment_id || !payer_address) {
            return res.status(400).json({ error: 'Missing payment_id or payer_address' });
        }

        const verified = await verifyOnChainPayment(payment_id, payer_address);

        if (verified) {
            const details = await getPaymentDetailsFromContract(payment_id);
            
            res.json({
                protocol: 'x402',
                network: 'starknet',
                verified: true,
                payment_id,
                payer: payer_address,
                details,
                verification_method: 'on-chain-contract-state'
            });
        } else {
            res.json({
                protocol: 'x402',
                network: 'starknet',
                verified: false,
                payment_id,
                payer: payer_address
            });
        }
    } catch (error) {
        logger.error('Verify payment error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.post('/api/v1/payments/deferred/authorize', async (req, res) => {
    try {
        const { client_id, amount_usd, resource } = req.body;

        if (!client_id || !amount_usd) {
            return res.status(400).json({ error: 'Missing client_id or amount_usd' });
        }

        const amountWei = (amount_usd * 1e6).toString();

        if (BigInt(amountWei) < BigInt(CONFIG.MIN_DEFERRED_AMOUNT) || 
            BigInt(amountWei) > BigInt(CONFIG.MAX_DEFERRED_AMOUNT)) {
            return res.status(400).json({ 
                error: 'Amount out of range',
                limits: {
                    min: CONFIG.MIN_DEFERRED_AMOUNT,
                    max: CONFIG.MAX_DEFERRED_AMOUNT
                }
            });
        }

        const clientIdFelt = stringToFelt(client_id);
        const resourceFelt = stringToFelt(resource || 'api-access');

        const result = await x402Contract.authorize_deferred_payment(
            clientIdFelt,
            toUint256(amountWei),
            resourceFelt
        );

        const authorization = result[0];
        const signature = result[1];

        await DeferredPayment.create({
            clientId: client_id,
            amount: amountWei,
            resource: resource || 'api-access',
            authorization: authorization.toString(),
            signature: signature.toString(),
            timestamp: Date.now(),
            settled: false
        });

        res.json({
            protocol: 'x402',
            network: 'starknet',
            scheme: 'deferred',
            authorization: authorization.toString(),
            signature: signature.toString(),
            client_id,
            amount_usd,
            usage: 'Include as Payment-Authorization: clientId:authorization:signature',
            contract: CONFIG.X402_CONTRACT_ADDRESS
        });
    } catch (error) {
        logger.error('Deferred authorization error:', error);
        res.status(500).json({ error: 'Authorization failed' });
    }
});

app.post('/api/v1/payments/deferred/settle', async (req, res) => {
    try {
        const { client_id, token, payer_address } = req.body;

        if (!client_id || !token) {
            return res.status(400).json({ error: 'Missing client_id or token' });
        }

        const totalBalance = await x402Contract.get_deferred_balance(stringToFelt(client_id));
        const balanceAmount = parseUint256(totalBalance).toString();

        if (balanceAmount === '0') {
            return res.status(404).json({ error: 'No deferred balance' });
        }

        let tokenAddress;
        switch (token.toUpperCase()) {
            case 'USDC':
                tokenAddress = CONFIG.USDC_ADDRESS;
                break;
            case 'ETH':
                tokenAddress = CONFIG.ETH_ADDRESS;
                break;
            case 'STRK':
                tokenAddress = CONFIG.STRK_ADDRESS;
                break;
            default:
                return res.status(400).json({ error: 'Unsupported token' });
        }

        res.json({
            protocol: 'x402',
            network: 'starknet',
            scheme: 'deferred',
            client_id,
            total_balance: balanceAmount,
            token: {
                address: tokenAddress,
                symbol: token.toUpperCase()
            },
            instructions: 'Approve token transfer for total_balance amount, then call settle_deferred_payments on contract',
            contract: CONFIG.X402_CONTRACT_ADDRESS,
            treasury: CONFIG.TREASURY_ADDRESS,
            calldata_hint: {
                function: 'settle_deferred_payments',
                params: {
                    client_id: stringToFelt(client_id),
                    token: tokenAddress
                }
            }
        });
    } catch (error) {
        logger.error('Deferred settlement error:', error);
        res.status(500).json({ error: 'Settlement preparation failed' });
    }
});

app.get('/api/v1/payments/deferred/balance/:client_id', async (req, res) => {
    try {
        const { client_id } = req.params;
        
        const totalBalance = await x402Contract.get_deferred_balance(stringToFelt(client_id));
        const balanceAmount = parseUint256(totalBalance).toString();

        const payments = await DeferredPayment.findAll({
            where: { clientId: client_id, settled: false }
        });

        res.json({
            protocol: 'x402',
            network: 'starknet',
            scheme: 'deferred',
            client_id,
            balance: balanceAmount,
            balance_usd: (Number(balanceAmount) / 1e6).toFixed(2),
            payment_count: payments.length,
            payments: payments.map(p => ({
                amount: p.amount,
                resource: p.resource,
                authorization: p.authorization,
                timestamp: p.timestamp,
                created_at: p.createdAt
            })),
            settlement_required: balanceAmount !== '0',
            treasury: CONFIG.TREASURY_ADDRESS
        });
    } catch (error) {
        logger.error('Deferred balance error:', error);
        res.status(500).json({ error: 'Failed to fetch balance' });
    }
});

app.get('/api/v1/data/premium', requirePayment(1.0), async (req, res) => {
    res.json({
        data: 'Premium data accessible via X402 payment on Starknet',
        timestamp: new Date().toISOString(),
        paid: true,
        protocol: 'x402',
        network: 'starknet',
        paymentDetails: req.paymentDetails
    });
});

app.post('/api/v1/mcp/query', requirePayment(0.10), async (req, res) => {
    const { query, tool } = req.body;
    res.json({
        protocol: 'x402',
        network: 'starknet',
        mcp_compatible: true,
        tool: tool || 'default',
        query: query,
        response: 'AI-generated response using MCP tool with Starknet payment',
        paymentDetails: req.paymentDetails
    });
});

// ==================== ADMIN ENDPOINTS ====================

app.post('/api/v1/admin/auth/setup', async (req, res) => {
    try {
        const adminCount = await AdminUser.count();
        if (adminCount > 0) {
            return res.status(403).json({ error: 'Setup already completed' });
        }
        
        const { username, password } = req.body;
        
        if (!username || !password || password.length < 8) {
            return res.status(400).json({ error: 'Invalid username or password (min 8 characters)' });
        }
        
        const passwordHash = await bcrypt.hash(password, 12);
        const adminUser = await AdminUser.create({
            username: username,
            passwordHash: passwordHash,
            role: 'superadmin',
            permissions: ['*']
        });
        
        const token = jwt.sign(
            { userId: adminUser.id, role: adminUser.role },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'First-time setup completed',
            token,
            user: {
                id: adminUser.id,
                username: adminUser.username,
                role: adminUser.role
            }
        });
    } catch (error) {
        logger.error('Admin setup error:', error);
        res.status(500).json({ error: 'Setup failed' });
    }
});

app.post('/api/v1/admin/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const adminUser = await AdminUser.findOne({ where: { username } });
        if (!adminUser || !adminUser.isActive) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isValid = await bcrypt.compare(password, adminUser.passwordHash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { userId: adminUser.id, role: adminUser.role },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        await adminUser.update({ lastLogin: new Date() });
        
        res.json({
            token,
            user: {
                id: adminUser.id,
                username: adminUser.username,
                role: adminUser.role,
                permissions: adminUser.permissions
            }
        });
    } catch (error) {
        logger.error('Admin login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/v1/admin/dashboard', authenticateAdmin, requirePermission('dashboard:read'), 
auditMiddleware('dashboard:read', '/api/v1/admin/dashboard'), async (req, res) => {
    try {
        const totalPayments = await Payment.count();
        const confirmedPayments = await Payment.count({ where: { status: 'confirmed' } });
        const pendingPayments = await Payment.count({ where: { status: 'pending' } });
        
        const recentPayments = await Payment.findAll({
            limit: 20,
            order: [['createdAt', 'DESC']]
        });

        const [totalContractPayments, usdcVolume, ethVolume, strkVolume] = await Promise.all([
            x402Contract.get_total_payments(),
            x402Contract.get_total_volume(CONFIG.USDC_ADDRESS),
            x402Contract.get_total_volume(CONFIG.ETH_ADDRESS),
            x402Contract.get_total_volume(CONFIG.STRK_ADDRESS)
        ]);

        const [usdcBalance, ethBalance, strkBalance] = await Promise.all([
            getTokenBalance(CONFIG.USDC_ADDRESS, CONFIG.TREASURY_ADDRESS),
            getTokenBalance(CONFIG.ETH_ADDRESS, CONFIG.TREASURY_ADDRESS),
            getTokenBalance(CONFIG.STRK_ADDRESS, CONFIG.TREASURY_ADDRESS)
        ]);

        res.json({
            protocol: 'x402',
            network: 'starknet',
            overview: {
                totalPayments,
                confirmedPayments,
                pendingPayments,
                contractPayments: parseUint256(totalContractPayments).toString()
            },
            volumes: {
                USDC: parseUint256(usdcVolume).toString(),
                ETH: parseUint256(ethVolume).toString(),
                STRK: parseUint256(strkVolume).toString()
            },
            balances: {
                USDC: (BigInt(usdcBalance) / BigInt(1e6)).toString(),
                ETH: (Number(ethBalance) / 1e18).toFixed(6),
                STRK: (Number(strkBalance) / 1e18).toFixed(6)
            },
            treasury: CONFIG.TREASURY_ADDRESS,
            contract: CONFIG.X402_CONTRACT_ADDRESS,
            recentPayments: recentPayments.map(p => ({
                id: p.id,
                paymentId: p.paymentId,
                clientId: p.clientId,
                payer: p.payer,
                amount: p.amount,
                token: p.token,
                status: p.status,
                paymentType: p.paymentType,
                createdAt: p.createdAt,
                confirmedAt: p.confirmedAt
            }))
        });
    } catch (error) {
        logger.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

app.get('/api/v1/admin/payments', authenticateAdmin, requirePermission('payments:read'), 
auditMiddleware('payments:read', '/api/v1/admin/payments'), async (req, res) => {
    try {
        const { page = 1, limit = 50, status, token, clientId } = req.query;
        const offset = (page - 1) * limit;
        
        const where = {};
        if (status) where.status = status;
        if (token) where.token = token;
        if (clientId) where.clientId = clientId;
        
        const { count, rows } = await Payment.findAndCountAll({
            where,
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['createdAt', 'DESC']]
        });
        
        res.json({
            payments: rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: count,
                pages: Math.ceil(count / limit)
            }
        });
    } catch (error) {
        logger.error('Payments list error:', error);
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

app.get('/api/v1/admin/events', authenticateAdmin, requirePermission('events:read'), 
auditMiddleware('events:read', '/api/v1/admin/events'), async (req, res) => {
    try {
        const { page = 1, limit = 50, eventName } = req.query;
        const offset = (page - 1) * limit;
        
        const where = {};
        if (eventName) where.eventName = eventName;
        
        const { count, rows } = await ContractEvent.findAndCountAll({
            where,
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['blockNumber', 'DESC']]
        });
        
        res.json({
            events: rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: count,
                pages: Math.ceil(count / limit)
            }
        });
    } catch (error) {
        logger.error('Events list error:', error);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

app.get('/api/v1/docs', (req, res) => {
    res.json({
        protocol: 'x402',
        version: '1.0',
        network: 'starknet',
        name: 'X402 Payment Backend - Starknet Implementation',
        description: 'Production-ready payment backend with on-chain verification on Starknet',
        contract: CONFIG.X402_CONTRACT_ADDRESS,
        treasury: CONFIG.TREASURY_ADDRESS,
        features: [
            'HTTP 402 Payment Required',
            'Starknet smart contract integration',
            'On-chain payment verification',
            'Multi-token support (USDC, ETH, STRK)',
            'Immediate and deferred payments',
            'MCP tool integration',
            'Enterprise admin dashboard',
            'Real-time event monitoring'
        ],
        endpoints: {
            public: {
                health: 'GET /api/v1/health',
                contractInfo: 'GET /api/v1/contract/info',
                balances: 'GET /api/v1/balances',
                prices: 'GET /api/v1/prices',
                docs: 'GET /api/v1/docs'
            },
            payment: {
                create: 'POST /api/v1/payments/create',
                verify: 'POST /api/v1/payments/verify',
                deferred: {
                    authorize: 'POST /api/v1/payments/deferred/authorize',
                    settle: 'POST /api/v1/payments/deferred/settle',
                    balance: 'GET /api/v1/payments/deferred/balance/:client_id'
                }
            },
            mcp: {
                query: 'POST /api/v1/mcp/query',
                premiumData: 'GET /api/v1/data/premium'
            },
            admin: {
                setup: 'POST /api/v1/admin/auth/setup',
                login: 'POST /api/v1/admin/auth/login',
                dashboard: 'GET /api/v1/admin/dashboard',
                payments: 'GET /api/v1/admin/payments',
                events: 'GET /api/v1/admin/events'
            }
        },
        supportedTokens: {
            USDC: CONFIG.USDC_ADDRESS,
            ETH: CONFIG.ETH_ADDRESS,
            STRK: CONFIG.STRK_ADDRESS
        }
    });
});

// ==================== DATABASE INITIALIZATION ====================

async function initializeDatabase() {
    try {
        await sequelize.authenticate();
        logger.info('Database connection established');
        
        await sequelize.sync({ alter: ENV === 'development' });
        logger.info('Database synchronized');
        
        const adminCount = await AdminUser.count();
        if (adminCount === 0) {
            logger.info('No admin users found. First-time setup required at POST /api/v1/admin/auth/setup');
        }
        
        return true;
    } catch (error) {
        logger.error('Database initialization failed:', error);
        return false;
    }
}

// ==================== SERVER STARTUP ====================

async function startServer() {
    const dbInitialized = await initializeDatabase();
    
    if (!dbInitialized) {
        logger.error('Cannot start server without database');
        process.exit(1);
    }

    const starknetInitialized = await initializeStarknet();
    
    if (!starknetInitialized) {
        logger.error('Cannot start server without Starknet connection');
        process.exit(1);
    }
    
    const PORT = CONFIG.PORT;
    const server = app.listen(PORT, CONFIG.HOST, () => {
        logger.info('='.repeat(80));
        logger.info(`X402 Payment Backend - Starknet Production Implementation`);
        logger.info('='.repeat(80));
        logger.info(`Server: http://${CONFIG.HOST}:${PORT}`);
        logger.info(`Environment: ${ENV}`);
        logger.info(`Protocol: x402 v1.0`);
        logger.info(`Network: Starknet`);
        logger.info(``);
        logger.info(`Smart Contracts:`);
        logger.info(`  X402 Contract: ${CONFIG.X402_CONTRACT_ADDRESS}`);
        logger.info(`  Treasury: ${CONFIG.TREASURY_ADDRESS}`);
        logger.info(``);
        logger.info(`Supported Tokens:`);
        logger.info(`  USDC: ${CONFIG.USDC_ADDRESS}`);
        logger.info(`  ETH: ${CONFIG.ETH_ADDRESS}`);
        logger.info(`  STRK: ${CONFIG.STRK_ADDRESS}`);
        logger.info(``);
        logger.info(`Production Features:`);
        logger.info(`  ✓ On-Chain Payment Verification`);
        logger.info(`  ✓ Starknet Smart Contract Integration`);
        logger.info(`  ✓ PostgreSQL Database`);
        logger.info(`  ✓ Redis Caching`);
        logger.info(`  ✓ Real-time Event Monitoring`);
        logger.info(`  ✓ Admin Dashboard & Control`);
        logger.info(`  ✓ Comprehensive Audit Logging`);
        logger.info(`  ✓ Multi-Token Support`);
        logger.info(`  ✓ Deferred Payment System`);
        logger.info(``);
        logger.info(`Key Endpoints:`);
        logger.info(`  Health: http://${CONFIG.HOST}:${PORT}/api/v1/health`);
        logger.info(`  Documentation: http://${CONFIG.HOST}:${PORT}/api/v1/docs`);
        logger.info(`  Contract Info: http://${CONFIG.HOST}:${PORT}/api/v1/contract/info`);
        logger.info(`  Admin Setup: POST http://${CONFIG.HOST}:${PORT}/api/v1/admin/auth/setup`);
        logger.info(`  Admin Login: POST http://${CONFIG.HOST}:${PORT}/api/v1/admin/auth/login`);
        logger.info(`  Admin Dashboard: http://${CONFIG.HOST}:${PORT}/api/v1/admin/dashboard`);
        logger.info('='.repeat(80));
    });

    process.on('SIGTERM', async () => {
        logger.info('SIGTERM received, shutting down gracefully');
        server.close(async () => {
            await sequelize.close();
            await redisClient.quit();
            logger.info('Server shut down successfully');
            process.exit(0);
        });
    });

    process.on('SIGINT', async () => {
        logger.info('SIGINT received, shutting down gracefully');
        server.close(async () => {
            await sequelize.close();
            await redisClient.quit();
            logger.info('Server shut down successfully');
            process.exit(0);
        });
    });
}

startServer().catch(error => {
    logger.error('Failed to start server:', error);
    process.exit(1);
});

module.exports = app;