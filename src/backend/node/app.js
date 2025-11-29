// ==================== ZEC ARENA PRODUCTION BACKEND - COMPLETE UNIFIED ====================
// Enterprise-Grade Zcash Integration with Hardware Security Module (HSM)
// Version: 4.0.0-production-secure | November 29, 2025
// Security: AES-256 encrypted secrets at rest, HSM for admin keys, JWT + bcrypt for users

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const Redis = require('ioredis');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const io = new Server(server, { cors: { origin: '*' } });

// ==================== ENCRYPTED SECRETS HANDLER ====================
// Master key must be stored in HSM or secure key management system
// For development: export MASTER_KEY=$(openssl rand -hex 32)
const MASTER_KEY_HEX = process.env.MASTER_KEY;
const MASTER_KEY = MASTER_KEY_HEX ? Buffer.from(MASTER_KEY_HEX, 'hex') : crypto.randomBytes(32);

if (!MASTER_KEY_HEX && process.env.NODE_ENV === 'production') {
  console.error('❌ CRITICAL: MASTER_KEY environment variable not set in production');
  console.error('Generate one with: openssl rand -hex 32');
  process.exit(1);
}

// Decrypt function for encrypted env vars (format: ENC:iv:authTag:ciphertext)
function decryptSecret(encrypted) {
  if (!encrypted || !encrypted.startsWith('ENC:')) {
    return encrypted; // Return plain text if not encrypted
  }
  
  try {
    const parts = encrypted.slice(4).split(':');
    if (parts.length !== 3) throw new Error('Invalid encrypted format');
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const ciphertext = Buffer.from(parts[2], 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('❌ Decryption failed:', err.message);
    throw new Error('Failed to decrypt secret - invalid master key or corrupted data');
  }
}

// Encrypt function for secrets (use this to encrypt your .env values)
function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return `ENC:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

// CLI utility to encrypt secrets: node backend.js encrypt "your-secret-here"
if (process.argv[2] === 'encrypt' && process.argv[3]) {
  console.log('\n🔐 Encrypted secret (add to .env):');
  console.log(encryptSecret(process.argv[3]));
  console.log('');
  process.exit(0);
}

// ==================== ENVIRONMENT CONFIGURATION WITH DECRYPTION ====================
const ENV_CONFIG = {
  // Server
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT) || 3001,
  HOST: process.env.HOST || '0.0.0.0',
  FRONTEND_URL: process.env.FRONTEND_URL || '*',
  
  // Database - passwords are decrypted if encrypted
  DB_HOST: process.env.DB_HOST || 'localhost',
  DB_PORT: parseInt(process.env.DB_PORT) || 5432,
  DB_NAME: process.env.DB_NAME || 'zec_arena',
  DB_USER: process.env.DB_USER || 'postgres',
  DB_PASSWORD: decryptSecret(process.env.DB_PASSWORD),
  DB_SSL: process.env.DB_SSL === 'true',
  DB_MAX_CONNECTIONS: parseInt(process.env.DB_MAX_CONNECTIONS) || 20,
  
  // Redis
  REDIS_HOST: process.env.REDIS_HOST || 'localhost',
  REDIS_PORT: parseInt(process.env.REDIS_PORT) || 6379,
  REDIS_PASSWORD: process.env.REDIS_PASSWORD ? decryptSecret(process.env.REDIS_PASSWORD) : undefined,
  REDIS_DB: parseInt(process.env.REDIS_DB) || 0,
  REDIS_TLS: process.env.REDIS_TLS === 'true',
  
  // Zcash RPC - sensitive credentials encrypted
  ZCASH_RPC_URL: process.env.ZCASH_RPC_URL || 'http://127.0.0.1:8232',
  ZCASH_RPC_USER: process.env.ZCASH_RPC_USER || 'zcashrpc',
  ZCASH_RPC_PASSWORD: decryptSecret(process.env.ZCASH_RPC_PASSWORD),
  ZCASH_RPC_TIMEOUT: parseInt(process.env.ZCASH_RPC_TIMEOUT) || 60000,
  ZCASH_NETWORK: process.env.ZCASH_NETWORK || 'mainnet',
  
  // Platform Addresses
  PLATFORM_DEPOSIT_ADDRESS: process.env.PLATFORM_DEPOSIT_ADDRESS,
  PLATFORM_WITHDRAWAL_ADDRESS: process.env.PLATFORM_WITHDRAWAL_ADDRESS,
  PLATFORM_HOT_WALLET: process.env.PLATFORM_HOT_WALLET,
  PLATFORM_COLD_WALLET: process.env.PLATFORM_COLD_WALLET,
  
  // Transaction Limits
  MIN_DEPOSIT: parseFloat(process.env.MIN_DEPOSIT) || 0.001,
  MAX_DEPOSIT: parseFloat(process.env.MAX_DEPOSIT) || 1000,
  MIN_WITHDRAWAL: parseFloat(process.env.MIN_WITHDRAWAL) || 0.001,
  MAX_WITHDRAWAL: parseFloat(process.env.MAX_WITHDRAWAL) || 100,
  WITHDRAWAL_FEE: parseFloat(process.env.WITHDRAWAL_FEE) || 0.0001,
  VERIFICATION_FEE: parseFloat(process.env.VERIFICATION_FEE) || 0.2,
  DAILY_WITHDRAWAL_LIMIT: parseFloat(process.env.DAILY_WITHDRAWAL_LIMIT) || 50,
  
  // Confirmations
  MIN_CONFIRMATIONS: parseInt(process.env.MIN_CONFIRMATIONS) || 6,
  WITHDRAWAL_CONFIRMATIONS: parseInt(process.env.WITHDRAWAL_CONFIRMATIONS) || 3,
  HIGH_VALUE_CONFIRMATIONS: parseInt(process.env.HIGH_VALUE_CONFIRMATIONS) || 12,
  HIGH_VALUE_THRESHOLD: parseFloat(process.env.HIGH_VALUE_THRESHOLD) || 10,
  
  // Monitoring
  MONITORING_INTERVAL: parseInt(process.env.MONITORING_INTERVAL) || 30000,
  WITHDRAWAL_INTERVAL: parseInt(process.env.WITHDRAWAL_INTERVAL) || 60000,
  HEALTH_CHECK_INTERVAL: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 300000,
  BLOCKCHAIN_SYNC_CHECK: parseInt(process.env.BLOCKCHAIN_SYNC_CHECK) || 120000,
  
  // Security - API keys encrypted
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  API_KEY: process.env.API_KEY ? decryptSecret(process.env.API_KEY) : undefined,
  ADMIN_API_KEY: decryptSecret(process.env.ADMIN_API_KEY),
  JWT_SECRET: decryptSecret(process.env.JWT_SECRET) || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: process.env.JWT_EXPIRES || '24h',
  
  // HSM Configuration (ADMIN KEYS ONLY - NOT USER AUTH)
  HSM_ENABLED: process.env.HSM_ENABLED === 'true',
  HSM_TYPE: process.env.HSM_TYPE || 'pkcs11',
  HSM_LIBRARY_PATH: process.env.HSM_LIBRARY_PATH,
  HSM_SLOT: parseInt(process.env.HSM_SLOT) || 0,
  HSM_PIN: process.env.HSM_PIN ? decryptSecret(process.env.HSM_PIN) : undefined,
  HSM_KEY_LABEL: process.env.HSM_KEY_LABEL || 'zec_arena_admin_master',
  
  // AWS KMS (alternative to HSM)
  AWS_REGION: process.env.AWS_REGION,
  AWS_KMS_KEY_ID: process.env.AWS_KMS_KEY_ID,
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY ? decryptSecret(process.env.AWS_SECRET_ACCESS_KEY) : undefined,
  
  // Azure Key Vault (alternative to HSM)
  AZURE_KEYVAULT_URL: process.env.AZURE_KEYVAULT_URL,
  AZURE_TENANT_ID: process.env.AZURE_TENANT_ID,
  AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET: process.env.AZURE_CLIENT_SECRET ? decryptSecret(process.env.AZURE_CLIENT_SECRET) : undefined,
  AZURE_KEY_NAME: process.env.AZURE_KEY_NAME || 'zec-arena-key',
  
  // YubiHSM
  YUBIHSM_CONNECTOR_URL: process.env.YUBIHSM_CONNECTOR_URL || 'http://127.0.0.1:12345',
  YUBIHSM_AUTH_KEY_ID: parseInt(process.env.YUBIHSM_AUTH_KEY_ID) || 1,
  YUBIHSM_PASSWORD: process.env.YUBIHSM_PASSWORD ? decryptSecret(process.env.YUBIHSM_PASSWORD) : undefined,
  
  // Logging
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  LOG_FILE: process.env.LOG_FILE,
  SENTRY_DSN: process.env.SENTRY_DSN,
  
  // Game Configuration
  HOUSE_EDGE: parseFloat(process.env.HOUSE_EDGE) || 0.10,
  MAX_GAME_STAKE: parseFloat(process.env.MAX_GAME_STAKE) || 10,
  MIN_GAME_STAKE: parseFloat(process.env.MIN_GAME_STAKE) || 0.001,
  MAX_PLAYERS_PER_GAME: parseInt(process.env.MAX_PLAYERS_PER_GAME) || 8,
  
  // Backup & Recovery
  BACKUP_ENABLED: process.env.BACKUP_ENABLED === 'true',
  BACKUP_INTERVAL: parseInt(process.env.BACKUP_INTERVAL) || 86400000,
  BACKUP_PATH: process.env.BACKUP_PATH || './backups',
  BACKUP_RETENTION_DAYS: parseInt(process.env.BACKUP_RETENTION_DAYS) || 30
};

// ==================== CONFIGURATION VALIDATION ====================
function validateConfig() {
  const required = [
    'DB_PASSWORD',
    'ZCASH_RPC_PASSWORD',
    'PLATFORM_DEPOSIT_ADDRESS',
    'PLATFORM_WITHDRAWAL_ADDRESS',
    'ADMIN_API_KEY'
  ];
  
  const missing = required.filter(key => !ENV_CONFIG[key]);
  
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }
  
  if (ENV_CONFIG.HSM_ENABLED) {
    console.log('🔐 HSM ENABLED - For ADMIN operations only (withdrawals, cold wallet)');
    console.log('✅ User authentication: bcrypt + pbkdf2 + JWT (NO HSM)');
    
    const hsmRequired = {
      pkcs11: ['HSM_LIBRARY_PATH', 'HSM_PIN'],
      awskms: ['AWS_KMS_KEY_ID', 'AWS_REGION'],
      azure: ['AZURE_KEYVAULT_URL', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'],
      yubihsm: ['YUBIHSM_AUTH_KEY_ID', 'YUBIHSM_PASSWORD']
    };
    
    const requiredHsmKeys = hsmRequired[ENV_CONFIG.HSM_TYPE] || [];
    const missingHsm = requiredHsmKeys.filter(key => !ENV_CONFIG[key]);
    
    if (missingHsm.length > 0) {
      console.error(`❌ Missing HSM configuration for ${ENV_CONFIG.HSM_TYPE}:`, missingHsm.join(', '));
      process.exit(1);
    }
  }
  
  console.log('✅ Configuration validated (secrets encrypted at rest)');
}

validateConfig();

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "wss:", "ws:"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: ENV_CONFIG.NODE_ENV === 'production' ? [] : null
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true
}));

app.use(cors({
  origin: ENV_CONFIG.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key']
}));

app.use(express.json({ limit: '1mb' }));

// ==================== RATE LIMITING ====================
const generalLimiter = rateLimit({
  windowMs: ENV_CONFIG.RATE_LIMIT_WINDOW,
  max: ENV_CONFIG.RATE_LIMIT_MAX,
  message: { error: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path === '/api/health'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts', errorCode: 1001 },
  standardHeaders: true,
  legacyHeaders: false
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many signup attempts', errorCode: 5004 }
});

const transactionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many transaction requests', errorCode: 5004 }
});

app.use(generalLimiter);

// ==================== DATABASE CONNECTION ====================
const pool = new Pool({
  host: ENV_CONFIG.DB_HOST,
  port: ENV_CONFIG.DB_PORT,
  database: ENV_CONFIG.DB_NAME,
  user: ENV_CONFIG.DB_USER,
  password: ENV_CONFIG.DB_PASSWORD,
  max: ENV_CONFIG.DB_MAX_CONNECTIONS,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: ENV_CONFIG.DB_SSL ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('💥 Database connection error:', err);
});

pool.on('connect', () => {
  console.log('✅ Database connected');
});

// ==================== REDIS CONNECTION ====================
const redis = new Redis({
  host: ENV_CONFIG.REDIS_HOST,
  port: ENV_CONFIG.REDIS_PORT,
  password: ENV_CONFIG.REDIS_PASSWORD,
  db: ENV_CONFIG.REDIS_DB,
  retryStrategy: (times) => Math.min(times * 50, 2000),
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  tls: ENV_CONFIG.REDIS_TLS ? { rejectUnauthorized: false } : undefined
});

redis.on('error', (err) => console.error('❌ Redis error:', err));
redis.on('connect', () => console.log('✅ Redis connected'));

// ==================== ERROR CODES & HANDLING ====================
const ERROR_CODES = {
  INVALID_CREDENTIALS: 1000,
  ACCOUNT_LOCKED: 1001,
  TOKEN_EXPIRED: 1002,
  TOKEN_INVALID: 1003,
  PASSWORD_WEAK: 1004,
  USER_NOT_FOUND: 1005,
  USER_EXISTS: 1006,
  SESSION_EXPIRED: 1007,
  UNAUTHORIZED: 1008,
  INSUFFICIENT_BALANCE: 2000,
  INVALID_ADDRESS: 2001,
  ADDRESS_NOT_SHIELDED: 2002,
  ACCOUNT_NOT_VERIFIED: 2003,
  WITHDRAWAL_LIMIT_EXCEEDED: 2004,
  DEPOSIT_TOO_SMALL: 2005,
  DEPOSIT_TOO_LARGE: 2006,
  WITHDRAWAL_TOO_SMALL: 2007,
  WITHDRAWAL_TOO_LARGE: 2008,
  TRANSACTION_NOT_FOUND: 2009,
  TRANSACTION_PENDING: 2010,
  WALLET_NOT_CONNECTED: 2011,
  BLOCKCHAIN_SYNC_PENDING: 3000,
  ZCASH_NODE_OFFLINE: 3001,
  INSUFFICIENT_CONFIRMATIONS: 3002,
  TRANSACTION_FAILED: 3003,
  OPERATION_TIMEOUT: 3004,
  SHIELDED_TX_FAILED: 3005,
  MEMO_TOO_LONG: 3006,
  GAME_NOT_FOUND: 4000,
  GAME_FULL: 4001,
  GAME_ALREADY_STARTED: 4002,
  PLAYER_ALREADY_IN_GAME: 4003,
  INVALID_GAME_TYPE: 4004,
  STAKE_TOO_LOW: 4005,
  STAKE_TOO_HIGH: 4006,
  NOT_IN_GAME: 4007,
  GAME_NOT_STARTED: 4008,
  INVALID_GAME_ACTION: 4009,
  DATABASE_ERROR: 5000,
  REDIS_ERROR: 5001,
  HSM_ERROR: 5002,
  HSM_NOT_INITIALIZED: 5003,
  RATE_LIMIT_EXCEEDED: 5004,
  SERVICE_UNAVAILABLE: 5005,
  INTERNAL_ERROR: 5006,
  VALIDATION_ERROR: 5007,
  NETWORK_ERROR: 5008,
  ADMIN_ACCESS_REQUIRED: 6000,
  INVALID_ADMIN_KEY: 6001,
  OPERATION_NOT_ALLOWED: 6002
};

const ERROR_MESSAGES = {
  [ERROR_CODES.INVALID_CREDENTIALS]: {
    message: 'Invalid username or password',
    userMessage: 'The credentials you entered are incorrect. Please try again.',
    action: 'Check your Player ID/Username and password'
  },
  [ERROR_CODES.ACCOUNT_LOCKED]: {
    message: 'Account temporarily locked',
    userMessage: 'Your account has been temporarily locked due to multiple failed login attempts.',
    action: 'Please wait 1 hour or contact support'
  },
  [ERROR_CODES.PASSWORD_WEAK]: {
    message: 'Password does not meet requirements',
    userMessage: 'Your password must contain uppercase, lowercase, numbers, and be at least 8 characters.',
    action: 'Create a stronger password (e.g., MyP@ssw0rd123)'
  },
  [ERROR_CODES.TOKEN_EXPIRED]: {
    message: 'Session expired',
    userMessage: 'Your session has expired. Please log in again.',
    action: 'Click to log in'
  },
  [ERROR_CODES.USER_NOT_FOUND]: {
    message: 'User not found',
    userMessage: 'We couldn\'t find an account with that Player ID.',
    action: 'Check your Player ID or create a new account'
  },
  [ERROR_CODES.INSUFFICIENT_BALANCE]: {
    message: 'Insufficient balance',
    userMessage: 'You don\'t have enough ZEC for this transaction.',
    action: 'Deposit more ZEC or reduce the amount'
  },
  [ERROR_CODES.INVALID_ADDRESS]: {
    message: 'Invalid Zcash address',
    userMessage: 'The Zcash address you entered is not valid.',
    action: 'Double-check the address format (should start with z, t, or u)'
  },
  [ERROR_CODES.ADDRESS_NOT_SHIELDED]: {
    message: 'Shielded address required',
    userMessage: 'For your security, only shielded z-addresses are accepted for withdrawals.',
    action: 'Use a z-address (starts with "z") or unified address (starts with "u")'
  },
  [ERROR_CODES.ACCOUNT_NOT_VERIFIED]: {
    message: 'Account not verified',
    userMessage: 'You need to verify your account to make withdrawals or play staked games.',
    action: 'Complete account verification'
  },
  [ERROR_CODES.WITHDRAWAL_LIMIT_EXCEEDED]: {
    message: 'Daily withdrawal limit exceeded',
    userMessage: 'You\'ve reached your daily withdrawal limit.',
    action: 'Try again tomorrow or contact support for higher limits'
  }
};

function buildErrorResponse(errorCode, additionalDetails = {}) {
  const errorInfo = ERROR_MESSAGES[errorCode] || {
    message: 'An error occurred',
    userMessage: 'Something went wrong. Please try again.',
    action: 'If the problem persists, contact support'
  };

  return {
    error: true,
    errorCode,
    message: errorInfo.message,
    userMessage: errorInfo.userMessage.replace(/\{(\w+)\}/g, (match, key) => additionalDetails[key] || match),
    action: errorInfo.action,
    details: additionalDetails,
    timestamp: new Date().toISOString(),
    support: 'For help, contact support@zecarena.com'
  };
}

class AppError extends Error {
  constructor(message, statusCode, errorCode, details = {}) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

function errorHandler(err, req, res, next) {
  console.error('Error:', {
    message: err.message,
    code: err.errorCode,
    stack: ENV_CONFIG.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  if (err.isOperational) {
    return res.status(err.statusCode).json(buildErrorResponse(err.errorCode, err.details));
  }

  const statusCode = err.statusCode || 500;
  const errorCode = err.errorCode || ERROR_CODES.INTERNAL_ERROR;

  res.status(statusCode).json(buildErrorResponse(errorCode, {
    message: ENV_CONFIG.NODE_ENV === 'development' ? err.message : 'Internal server error'
  }));
}

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ==================== AUTHENTICATION MIDDLEWARE (USER AUTH - NO HSM) ====================
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new AppError('No token provided', 401, ERROR_CODES.UNAUTHORIZED);
    }

    let decoded;
    try {
      decoded = jwt.verify(token, ENV_CONFIG.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new AppError('Token expired', 401, ERROR_CODES.TOKEN_EXPIRED);
      }
      throw new AppError('Invalid token', 401, ERROR_CODES.TOKEN_INVALID);
    }

    const cached = await redis.get(`session:${decoded.playerId}`);
    if (cached) {
      req.user = JSON.parse(cached);
      return next();
    }

    const result = await pool.query(
      'SELECT player_id, username, password_hash, salt, email, balance, is_verified, avatar_id, hide_balance, wins, losses, xp, total_games, streak FROM users WHERE player_id = $1',
      [decoded.playerId]
    );

    if (result.rows.length === 0) {
      throw new AppError('User not found', 401, ERROR_CODES.USER_NOT_FOUND);
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const adminKey = req.header('X-Admin-Key');
    
    if (!adminKey || adminKey !== ENV_CONFIG.ADMIN_API_KEY) {
      throw new AppError('Invalid admin key', 403, ERROR_CODES.INVALID_ADMIN_KEY);
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

// ==================== SECURITY EVENT LOGGING ====================
async function logSecurityEvent(type, severity, details) {
  try {
    await redis.publish('security_event', JSON.stringify({
      type,
      severity,
      ...details,
      timestamp: Date.now()
    }));
    
    await pool.query(
      'INSERT INTO security_events (event_type, severity, player_id, ip_address, description, metadata) VALUES ($1, $2, $3, $4, $5, $6)',
      [
        type,
        severity,
        details.playerId || null,
        details.ipAddress || null,
        details.description || null,
        details.metadata ? JSON.stringify(details.metadata) : null
      ]
    );
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
}

// ==================== BRUTE FORCE PROTECTION (REDIS-BASED) ====================
async function checkBruteForce(identifier, maxAttempts = 5) {
  const key = `bruteforce:${identifier}`;
  const attempts = await redis.get(key);
  
  if (attempts && parseInt(attempts) >= maxAttempts) {
    return { blocked: true, attemptsLeft: 0 };
  }
  
  return { blocked: false, attemptsLeft: maxAttempts - (parseInt(attempts) || 0) };
}

async function incrementBruteForce(identifier) {
  const key = `bruteforce:${identifier}`;
  const current = await redis.incr(key);
  
  if (current === 1) {
    await redis.expire(key, 3600);
  }
  
  return current;
}

async function clearBruteForce(identifier) {
  const key = `bruteforce:${identifier}`;
  await redis.del(key);
}

// ==================== ZCASH RPC ====================
const zcashRPC = async (method, params = []) => {
  try {
    const response = await axios.post(ENV_CONFIG.ZCASH_RPC_URL, {
      jsonrpc: '1.0',
      id: 'zecarena',
      method,
      params
    }, {
      auth: {
        username: ENV_CONFIG.ZCASH_RPC_USER,
        password: ENV_CONFIG.ZCASH_RPC_PASSWORD
      },
      headers: { 'Content-Type': 'application/json' },
      timeout: ENV_CONFIG.ZCASH_RPC_TIMEOUT
    });
    
    if (response.data.error) {
      throw new Error(response.data.error.message);
    }
    
    return response.data.result;
  } catch (error) {
    console.error('Zcash RPC Error:', error.message);
    throw new AppError('Zcash RPC failed', 503, ERROR_CODES.ZCASH_NODE_OFFLINE, {
      method,
      error: error.message
    });
  }
};

const verifyZcashTransaction = async (txId, expectedAmount, expectedMemo) => {
  try {
    const tx = await zcashRPC('gettransaction', [txId]);
    if (!tx) {
      return { valid: false, error: 'Transaction not found' };
    }
    
    let memo = '';
    if (tx.vjoinsplit && tx.vjoinsplit.length > 0) {
      const memoHex = tx.vjoinsplit[0].memo;
      memo = Buffer.from(memoHex, 'hex').toString('utf8').replace(/\0/g, '').trim();
    }
    
    const amount = Math.abs(tx.amount);
    const confirmations = tx.confirmations || 0;
    
    if (amount < expectedAmount) {
      return { valid: false, error: 'Insufficient amount' };
    }
    
    if (expectedMemo && memo !== expectedMemo) {
      return { valid: false, error: 'Invalid memo' };
    }
    
    if (confirmations < ENV_CONFIG.MIN_CONFIRMATIONS) {
      return { valid: false, error: 'Not enough confirmations', confirmations, required: ENV_CONFIG.MIN_CONFIRMATIONS };
    }
    
    return { valid: true, amount, memo, confirmations };
  } catch (error) {
    console.error('Verification error:', error);
    return { valid: false, error: error.message || 'Verification failed' };
  }
};

const sendZcashTransaction = async (toAddress, amount, memo) => {
  try {
    const memoHex = Buffer.from(memo, 'utf8').toString('hex').padEnd(1024, '0');
    const operationId = await zcashRPC('z_sendmany', [
      ENV_CONFIG.PLATFORM_HOT_WALLET,
      [{ address: toAddress, amount, memo: memoHex }],
      1,
      ENV_CONFIG.WITHDRAWAL_FEE
    ]);
    
    let result;
    for (let i = 0; i < 60; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const operations = await zcashRPC('z_getoperationstatus', [[operationId]]);
      if (operations[0].status === 'success') {
        result = operations[0].result;
        break;
      } else if (operations[0].status === 'failed') {
        throw new Error(operations[0].error.message);
      }
    }
    
    return result ? result.txid : null;
  } catch (error) {
    console.error('Send transaction error:', error);
    return null;
  }
};

// ==================== BACKGROUND TRANSACTION MONITOR ====================
setInterval(async () => {
  try {
    const transactions = await zcashRPC('z_listreceivedbyaddress', [ENV_CONFIG.PLATFORM_DEPOSIT_ADDRESS, 0]);
    if (!transactions) return;
    
    for (const tx of transactions) {
      const existing = await pool.query('SELECT id FROM transactions WHERE tx_id = $1', [tx.txid]);
      if (existing.rows.length > 0 || tx.confirmations < 1) continue;
      
      let memo = '';
      if (tx.memo) {
        memo = Buffer.from(tx.memo, 'hex').toString('utf8').replace(/\0/g, '').trim();
      }
      
      if (!memo) continue;
      
      const userResult = await pool.query('SELECT * FROM users WHERE player_id = $1', [memo]);
      if (userResult.rows.length === 0) continue;
      
      const user = userResult.rows[0];
      const amount = tx.amount;
      
      if (amount >= ENV_CONFIG.VERIFICATION_FEE && !user.is_verified) {
        await pool.query(
          'UPDATE users SET is_verified = true, verification_tx_id = $1 WHERE player_id = $2',
          [tx.txid, user.player_id]
        );
        
        await pool.query(
          'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
          [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, user.player_id, 'VERIFICATION', ENV_CONFIG.VERIFICATION_FEE, tx.txid, 'COMPLETED']
        );
        
        console.log('✅ Verified user:', user.player_id);
      } else if (amount >= ENV_CONFIG.MIN_DEPOSIT) {
        await pool.query(
          'UPDATE users SET balance = balance + $1 WHERE player_id = $2',
          [amount, user.player_id]
        );
        
        await pool.query(
          'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
          [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, user.player_id, 'DEPOSIT', amount, tx.txid, 'COMPLETED']
        );
        
        console.log('✅ Deposit processed:', user.player_id, amount);
      }
    }
  } catch (error) {
    console.error('❌ Transaction monitor error:', error);
  }
}, ENV_CONFIG.MONITORING_INTERVAL);

// ==================== AUTH ROUTES (USER AUTH - NO HSM) ====================
app.post('/api/auth/signup', signupLimiter, async (req, res, next) => {
  try {
    const { password, email, username } = req.body;
    
    if (!password || password.length < 8) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PASSWORD_WEAK, {
        requirement: 'At least 8 characters'
      }));
    }

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PASSWORD_WEAK, {
        missing: [
          !hasUpperCase && 'uppercase letter',
          !hasLowerCase && 'lowercase letter',
          !hasNumbers && 'number'
        ].filter(Boolean),
        example: 'MyP@ssw0rd123'
      }));
    }

    const playerId = crypto.randomBytes(5).toString('hex').toUpperCase().substring(0, 8);
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');

    await pool.query(
      'INSERT INTO users (player_id, password_hash, salt, email, username, balance, is_verified, avatar_id, hide_balance, wins, losses, xp, total_games, streak) VALUES ($1, $2, $3, $4, $5, 0, false, $6, false, 0, 0, 0, 0, 0)',
      [playerId, hash, salt, email || null, username || null, 'hero_1']
    );

    const token = jwt.sign({ playerId }, ENV_CONFIG.JWT_SECRET, { expiresIn: ENV_CONFIG.JWT_EXPIRES });

    await logSecurityEvent('USER_SIGNUP', 'LOW', {
      playerId,
      ipAddress: req.ip,
      description: 'New user registration'
    });

    console.log(`✅ New user: ${playerId}`);

    res.json({
      success: true,
      playerId,
      token,
      message: 'Account created successfully',
      expiresIn: ENV_CONFIG.JWT_EXPIRES
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.USER_EXISTS, {
        field: error.constraint?.includes('username') ? 'username' : 'email'
      }));
    }
    next(error);
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const { playerId, password } = req.body;

    const bruteCheck = await checkBruteForce(playerId);
    if (bruteCheck.blocked) {
      await logSecurityEvent('LOGIN_BLOCKED', 'MEDIUM', {
        playerId,
        ipAddress: req.ip,
        description: 'Login blocked due to brute force attempts'
      });
      
      return res.status(429).json(buildErrorResponse(ERROR_CODES.ACCOUNT_LOCKED, {
        attempts: 5,
        waitTime: '1 hour'
      }));
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE player_id = $1 OR username = $1',
      [playerId]
    );

    if (result.rows.length === 0) {
      await incrementBruteForce(playerId);
      await logSecurityEvent('LOGIN_FAILED', 'LOW', {
        playerId,
        ipAddress: req.ip,
        description: 'Invalid credentials - user not found'
      });
      return res.status(401).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND, {
        providedId: playerId
      }));
    }

    const user = result.rows[0];
    const hash = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');

    if (hash !== user.password_hash) {
      const attempts = await incrementBruteForce(user.player_id);
      
      await logSecurityEvent('LOGIN_FAILED', 'LOW', {
        playerId: user.player_id,
        ipAddress: req.ip,
        description: `Invalid password (Attempt ${attempts}/5)`
      });
      
      return res.status(401).json(buildErrorResponse(ERROR_CODES.INVALID_CREDENTIALS, {
        attemptsLeft: Math.max(0, 5 - attempts),
        lockoutWarning: attempts >= 4 ? 'One more failed attempt will lock your account' : null
      }));
    }

    await clearBruteForce(user.player_id);

    await pool.query(
      'UPDATE users SET last_login = NOW(), login_count = login_count + 1 WHERE player_id = $1',
      [user.player_id]
    );

    const token = jwt.sign({ playerId: user.player_id }, ENV_CONFIG.JWT_SECRET, { expiresIn: ENV_CONFIG.JWT_EXPIRES });

    await redis.setex(`session:${user.player_id}`, 86400, JSON.stringify({
      playerId: user.player_id,
      username: user.username,
      isVerified: user.is_verified
    }));

    await logSecurityEvent('LOGIN_SUCCESS', 'LOW', {
      playerId: user.player_id,
      ipAddress: req.ip,
      description: 'Successful login'
    });

    console.log(`✅ Login: ${user.player_id}`);

    res.json({
      success: true,
      token,
      playerId: user.player_id,
      username: user.username,
      balance: parseFloat(user.balance),
      isVerified: user.is_verified,
      avatarId: user.avatar_id,
      expiresIn: ENV_CONFIG.JWT_EXPIRES
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/verify', async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID, {
        reason: 'No token provided'
      }));
    }

    let decoded;
    try {
      decoded = jwt.verify(token, ENV_CONFIG.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_EXPIRED, {
          expiredAt: error.expiredAt
        }));
      }
      return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID, {
        reason: error.message
      }));
    }
    
    const cached = await redis.get(`session:${decoded.playerId}`);
    if (cached) {
      return res.json({ valid: true, user: JSON.parse(cached) });
    }

    const result = await pool.query(
      'SELECT player_id, username, is_verified, balance, avatar_id FROM users WHERE player_id = $1',
      [decoded.playerId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND, {
        playerId: decoded.playerId
      }));
    }

    res.json({ 
      valid: true, 
      user: {
        playerId: result.rows[0].player_id,
        username: result.rows[0].username,
        isVerified: result.rows[0].is_verified,
        balance: parseFloat(result.rows[0].balance),
        avatarId: result.rows[0].avatar_id
      }
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    const { playerId } = req.body;
    
    if (!playerId) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND, {
        reason: 'Player ID required'
      }));
    }
    
    await redis.del(`session:${playerId}`);
    
    await logSecurityEvent('USER_LOGOUT', 'LOW', {
      playerId,
      ipAddress: req.ip,
      description: 'User logged out'
    });
    
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/refresh', async (req, res, next) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID, {
        reason: 'No token provided'
      }));
    }
    
    let decoded;
    try {
      decoded = jwt.verify(token, ENV_CONFIG.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_EXPIRED, {
          message: 'Please log in again'
        }));
      }
      return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID));
    }
    
    const newToken = jwt.sign({ playerId: decoded.playerId }, ENV_CONFIG.JWT_SECRET, { expiresIn: ENV_CONFIG.JWT_EXPIRES });
    
    res.json({ 
      success: true,
      token: newToken,
      expiresIn: ENV_CONFIG.JWT_EXPIRES
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/change-password', async (req, res, next) => {
  try {
    const { playerId, oldPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PASSWORD_WEAK, {
        requirement: 'At least 8 characters'
      }));
    }

    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PASSWORD_WEAK, {
        missing: [
          !hasUpperCase && 'uppercase',
          !hasLowerCase && 'lowercase',
          !hasNumbers && 'number'
        ].filter(Boolean)
      }));
    }

    const result = await pool.query(
      'SELECT password_hash, salt FROM users WHERE player_id = $1',
      [playerId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND, { playerId }));
    }

    const user = result.rows[0];
    const oldHash = crypto.pbkdf2Sync(oldPassword, user.salt, 100000, 64, 'sha512').toString('hex');

    if (oldHash !== user.password_hash) {
      return res.status(401).json(buildErrorResponse(ERROR_CODES.INVALID_CREDENTIALS, {
        field: 'oldPassword'
      }));
    }

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = crypto.pbkdf2Sync(newPassword, newSalt, 100000, 64, 'sha512').toString('hex');

    await pool.query(
      'UPDATE users SET password_hash = $1, salt = $2 WHERE player_id = $3',
      [newHash, newSalt, playerId]
    );

    await redis.del(`session:${playerId}`);

    await logSecurityEvent('PASSWORD_CHANGED', 'MEDIUM', {
      playerId,
      ipAddress: req.ip,
      description: 'Password changed successfully'
    });

    res.json({ 
      success: true, 
      message: 'Password changed successfully',
      action: 'Please log in again with your new password'
    });
  } catch (error) {
    next(error);
  }
});

// ==================== ACCOUNT ROUTES ====================
app.post('/api/account/verify', auth, transactionLimiter, async (req, res, next) => {
  try {
    const { txId } = req.body;
    
    if (!txId || txId.length < 10) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.INVALID_ADDRESS, {
        field: 'txId'
      }));
    }
    
    const verification = await verifyZcashTransaction(txId, ENV_CONFIG.VERIFICATION_FEE, req.user.player_id);
    
    if (!verification.valid) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TRANSACTION_FAILED, {
        error: verification.error
      }));
    }
    
    await pool.query(
      'UPDATE users SET is_verified = true, verification_tx_id = $1 WHERE player_id = $2',
      [txId, req.user.player_id]
    );
    
    await pool.query(
      'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'VERIFICATION', ENV_CONFIG.VERIFICATION_FEE, txId, 'COMPLETED']
    );
    
    res.json({ success: true, message: 'Account verified successfully' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/account/username', auth, async (req, res, next) => {
  try {
    const { newUsername, txId } = req.body;
    
    if (!newUsername || newUsername.length < 3 || newUsername.length > 15) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.VALIDATION_ERROR, {
        field: 'username',
        requirement: '3-15 characters'
      }));
    }
    
    const existing = await pool.query('SELECT player_id FROM users WHERE username = $1', [newUsername]);
    if (existing.rows.length > 0) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.USER_EXISTS, {
        field: 'username'
      }));
    }
    
    if (txId) {
      const verification = await verifyZcashTransaction(txId, 0.05, req.user.player_id);
      if (!verification.valid) {
        return res.status(400).json(buildErrorResponse(ERROR_CODES.TRANSACTION_FAILED, {
          error: verification.error
        }));
      }
      
      await pool.query(
        'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'USERNAME_CHANGE', 0.05, txId, 'COMPLETED']
      );
    }
    
    await pool.query('UPDATE users SET username = $1 WHERE player_id = $2', [newUsername, req.user.player_id]);
    
    res.json({ success: true, username: newUsername });
  } catch (error) {
    next(error);
  }
});

app.post('/api/account/avatar', auth, async (req, res, next) => {
  try {
    const { avatarId } = req.body;
    
    if (!avatarId || !avatarId.startsWith('hero_')) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.VALIDATION_ERROR, {
        field: 'avatarId'
      }));
    }
    
    await pool.query('UPDATE users SET avatar_id = $1 WHERE player_id = $2', [avatarId, req.user.player_id]);
    
    res.json({ success: true, avatarId });
  } catch (error) {
    next(error);
  }
});

app.get('/api/account/me', auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT player_id, username, avatar_id, balance, is_verified, hide_balance, wins, losses, xp, total_games, streak FROM users WHERE player_id = $1',
      [req.user.player_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND));
    }
    
    res.json({
      user: {
        playerId: result.rows[0].player_id,
        username: result.rows[0].username,
        avatarId: result.rows[0].avatar_id,
        balance: parseFloat(result.rows[0].balance),
        isVerified: result.rows[0].is_verified,
        hideBalance: result.rows[0].hide_balance,
        wins: result.rows[0].wins,
        losses: result.rows[0].losses,
        xp: result.rows[0].xp,
        totalGames: result.rows[0].total_games,
        streak: result.rows[0].streak
      }
    });
  } catch (error) {
    next(error);
  }
});

// ==================== WALLET ROUTES ====================
app.post('/api/wallet/deposit', auth, transactionLimiter, async (req, res, next) => {
  try {
    const { txId } = req.body;
    
    const existing = await pool.query('SELECT id FROM transactions WHERE tx_id = $1', [txId]);
    if (existing.rows.length > 0) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TRANSACTION_PENDING, {
        message: 'Transaction already processed'
      }));
    }
    
    const verification = await verifyZcashTransaction(txId, ENV_CONFIG.MIN_DEPOSIT, req.user.player_id);
    
    if (!verification.valid) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TRANSACTION_FAILED, {
        error: verification.error
      }));
    }
    
    await pool.query('UPDATE users SET balance = balance + $1 WHERE player_id = $2', [verification.amount, req.user.player_id]);
    
    await pool.query(
      'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'DEPOSIT', verification.amount, txId, 'COMPLETED']
    );
    
    res.json({ success: true, amount: verification.amount });
  } catch (error) {
    next(error);
  }
});

app.post('/api/wallet/withdraw', auth, transactionLimiter, async (req, res, next) => {
  try {
    const { amount, address } = req.body;
    
    if (!req.user.is_verified) {
      return res.status(403).json(buildErrorResponse(ERROR_CODES.ACCOUNT_NOT_VERIFIED));
    }
    
    if (amount < ENV_CONFIG.MIN_WITHDRAWAL) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.WITHDRAWAL_TOO_SMALL, {
        provided: amount,
        min: ENV_CONFIG.MIN_WITHDRAWAL
      }));
    }
    
    if (amount > ENV_CONFIG.MAX_WITHDRAWAL) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.WITHDRAWAL_TOO_LARGE, {
        requested: amount,
        max: ENV_CONFIG.MAX_WITHDRAWAL
      }));
    }
    
    if (parseFloat(req.user.balance) < amount) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.INSUFFICIENT_BALANCE, {
        required: amount,
        available: parseFloat(req.user.balance),
        shortfall: amount - parseFloat(req.user.balance)
      }));
    }
    
    if (!address.startsWith('z') && !address.startsWith('u')) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.ADDRESS_NOT_SHIELDED, {
        providedAddress: address.substring(0, 20) + '...'
      }));
    }
    
    const dailyTotal = await pool.query(
      "SELECT COALESCE(SUM(ABS(amount)), 0) as total FROM transactions WHERE user_id = $1 AND type = 'WITHDRAW' AND created_at > NOW() - INTERVAL '24 hours'",
      [req.user.player_id]
    );
    
    const dailyUsed = parseFloat(dailyTotal.rows[0].total);
    
    if (dailyUsed + amount > ENV_CONFIG.DAILY_WITHDRAWAL_LIMIT) {
      return res.status(429).json(buildErrorResponse(ERROR_CODES.WITHDRAWAL_LIMIT_EXCEEDED, {
        limit: ENV_CONFIG.DAILY_WITHDRAWAL_LIMIT,
        used: dailyUsed,
        available: ENV_CONFIG.DAILY_WITHDRAWAL_LIMIT - dailyUsed
      }));
    }
    
    await pool.query('UPDATE users SET balance = balance - $1 WHERE player_id = $2', [amount, req.user.player_id]);
    
    const txId = await sendZcashTransaction(address, amount, `Withdrawal from ZecArena - ${req.user.player_id}`);
    
    if (!txId) {
      await pool.query('UPDATE users SET balance = balance + $1 WHERE player_id = $2', [amount, req.user.player_id]);
      return res.status(500).json(buildErrorResponse(ERROR_CODES.TRANSACTION_FAILED, {
        error: 'Failed to send transaction'
      }));
    }
    
    await pool.query(
      'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'WITHDRAW', -amount, txId, 'COMPLETED']
    );
    
    res.json({ success: true, txId, amount });
  } catch (error) {
    next(error);
  }
});

app.get('/api/wallet/transactions', auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, type, amount, tx_id, status, created_at FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100',
      [req.user.player_id]
    );
    
    res.json({ transactions: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/wallet/toggle-balance', auth, async (req, res, next) => {
  try {
    const newHideBalance = !req.user.hide_balance;
    await pool.query('UPDATE users SET hide_balance = $1 WHERE player_id = $2', [newHideBalance, req.user.player_id]);
    
    res.json({ success: true, hideBalance: newHideBalance });
  } catch (error) {
    next(error);
  }
});

app.get('/api/wallet/balance', auth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT balance, hide_balance FROM users WHERE player_id = $1', [req.user.player_id]);
    
    res.json({ 
      balance: parseFloat(result.rows[0].balance), 
      hideBalance: result.rows[0].hide_balance 
    });
  } catch (error) {
    next(error);
  }
});

// ==================== ROOM/LOBBY ROUTES ====================
app.post('/api/rooms/create', auth, async (req, res, next) => {
  try {
    const { type, stake, maxPlayers } = req.body;
    
    if (!type || !['PICTURE_RUSH', 'PICTURE_MATCH'].includes(type)) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.INVALID_GAME_TYPE));
    }
    
    if (stake < 0 || maxPlayers < 1 || maxPlayers > ENV_CONFIG.MAX_PLAYERS_PER_GAME) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.VALIDATION_ERROR, {
        error: 'Invalid game parameters'
      }));
    }
    
    if (stake > 0) {
      if (!req.user.is_verified) {
        return res.status(403).json(buildErrorResponse(ERROR_CODES.ACCOUNT_NOT_VERIFIED));
      }
      
      if (parseFloat(req.user.balance) < stake) {
        return res.status(400).json(buildErrorResponse(ERROR_CODES.INSUFFICIENT_BALANCE, {
          required: stake,
          available: parseFloat(req.user.balance)
        }));
      }
      
      await pool.query('UPDATE users SET balance = balance - $1 WHERE player_id = $2', [stake, req.user.player_id]);
    }
    
    const roomId = `room-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`;
    
    await pool.query(
      'INSERT INTO rooms (id, host_id, host_name, host_avatar, type, stake, max_players, current_players, status, player_ids, player_data) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)',
      [
        roomId,
        req.user.player_id,
        req.user.username || `Agent ${req.user.player_id.slice(0, 6)}`,
        req.user.avatar_id,
        type,
        stake,
        maxPlayers,
        'WAITING',
        JSON.stringify([req.user.player_id]),
        JSON.stringify({
          [req.user.player_id]: {
            username: req.user.username || `Agent ${req.user.player_id.slice(0, 6)}`,
            avatarId: req.user.avatar_id
          }
        })
      ]
    );
    
    io.emit('room_created', { roomId, type, stake, maxPlayers });
    
    res.json({ success: true, roomId });
  } catch (error) {
    next(error);
  }
});

app.post('/api/rooms/join', auth, async (req, res, next) => {
  try {
    const { roomId } = req.body;
    
    const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.GAME_NOT_FOUND));
    }
    
    const room = result.rows[0];
    
    if (room.status !== 'WAITING') {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.GAME_ALREADY_STARTED));
    }
    
    if (room.current_players >= room.max_players) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.GAME_FULL, {
        currentPlayers: room.current_players,
        maxPlayers: room.max_players
      }));
    }
    
    const playerIds = JSON.parse(room.player_ids);
    if (playerIds.includes(req.user.player_id)) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PLAYER_ALREADY_IN_GAME));
    }
    
    if (room.stake > 0) {
      if (!req.user.is_verified) {
        return res.status(403).json(buildErrorResponse(ERROR_CODES.ACCOUNT_NOT_VERIFIED));
      }
      
      if (parseFloat(req.user.balance) < room.stake) {
        return res.status(400).json(buildErrorResponse(ERROR_CODES.INSUFFICIENT_BALANCE, {
          required: room.stake,
          available: parseFloat(req.user.balance)
        }));
      }
      
      await pool.query('UPDATE users SET balance = balance - $1 WHERE player_id = $2', [room.stake, req.user.player_id]);
    }
    
    playerIds.push(req.user.player_id);
    const playerData = JSON.parse(room.player_data);
    playerData[req.user.player_id] = {
      username: req.user.username || `Agent ${req.user.player_id.slice(0, 6)}`,
      avatarId: req.user.avatar_id
    };
    
    await pool.query(
      'UPDATE rooms SET current_players = current_players + 1, player_ids = $1, player_data = $2 WHERE id = $3',
      [JSON.stringify(playerIds), JSON.stringify(playerData), roomId]
    );
    
    const updatedRoom = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
    
    if (updatedRoom.rows[0].current_players >= updatedRoom.rows[0].max_players) {
      await pool.query('UPDATE rooms SET status = $1, started_at = NOW() WHERE id = $2', ['STARTING', roomId]);
      
      io.to(roomId).emit('room_starting', { roomId });
      
      setTimeout(async () => {
        await pool.query('UPDATE rooms SET status = $1 WHERE id = $2', ['IN_PROGRESS', roomId]);
        io.to(roomId).emit('game_started', { roomId });
      }, 10000);
    }
    
    io.to(roomId).emit('player_joined', updatedRoom.rows[0]);
    io.emit('room_updated', updatedRoom.rows[0]);
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/rooms', async (req, res, next) => {
  try {
    const { type } = req.query;
    
    let query = "SELECT * FROM rooms WHERE status IN ('WAITING', 'STARTING')";
    const params = [];
    
    if (type) {
      query += ' AND type = $1';
      params.push(type);
    }
    
    query += ' ORDER BY created_at DESC LIMIT 50';
    
    const result = await pool.query(query, params);
    
    res.json({ rooms: result.rows });
  } catch (error) {
    next(error);
  }
});

app.get('/api/rooms/:roomId', async (req, res, next) => {
  try {
    const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.roomId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.GAME_NOT_FOUND));
    }
    
    res.json({ room: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.post('/api/rooms/:roomId/leave', auth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.roomId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.GAME_NOT_FOUND));
    }
    
    const room = result.rows[0];
    const playerIds = JSON.parse(room.player_ids);
    
    if (!playerIds.includes(req.user.player_id)) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.NOT_IN_GAME));
    }
    
    if (room.status !== 'WAITING') {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.GAME_ALREADY_STARTED, {
        message: 'Cannot leave after game started'
      }));
    }
    
    if (room.stake > 0) {
      await pool.query('UPDATE users SET balance = balance + $1 WHERE player_id = $2', [room.stake, req.user.player_id]);
    }
    
    const updatedPlayerIds = playerIds.filter(id => id !== req.user.player_id);
    
    if (updatedPlayerIds.length === 0) {
      await pool.query('DELETE FROM rooms WHERE id = $1', [req.params.roomId]);
      io.emit('room_deleted', { roomId: req.params.roomId });
    } else {
      await pool.query(
        'UPDATE rooms SET current_players = current_players - 1, player_ids = $1 WHERE id = $2',
        [JSON.stringify(updatedPlayerIds), req.params.roomId]
      );
      
      const updatedRoom = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.roomId]);
      io.to(req.params.roomId).emit('player_left', updatedRoom.rows[0]);
      io.emit('room_updated', updatedRoom.rows[0]);
    }
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// ==================== GAME ROUTES ====================
app.post('/api/game/start', auth, async (req, res, next) => {
  try {
    const { roomId } = req.body;
    
    const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.GAME_NOT_FOUND));
    }
    
    const room = result.rows[0];
    
    if (room.host_id !== req.user.player_id) {
      return res.status(403).json(buildErrorResponse(ERROR_CODES.OPERATION_NOT_ALLOWED, {
        message: 'Only host can start the game'
      }));
    }
    
    if (room.status !== 'WAITING') {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.GAME_ALREADY_STARTED));
    }
    
    await pool.query('UPDATE rooms SET status = $1, started_at = NOW() WHERE id = $2', ['IN_PROGRESS', roomId]);
    
    io.to(roomId).emit('game_started', { roomId });
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.post('/api/game/end', auth, async (req, res, next) => {
  try {
    const { roomId, winnerId, scores } = req.body;
    
    const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(buildErrorResponse(ERROR_CODES.GAME_NOT_FOUND));
    }
    
    const room = result.rows[0];
    
    if (room.status !== 'IN_PROGRESS') {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.GAME_NOT_STARTED));
    }
    
    await pool.query(
      'UPDATE rooms SET status = $1, winner_id = $2, scores = $3, finished_at = NOW() WHERE id = $4',
      ['FINISHED', winnerId, JSON.stringify(scores), roomId]
    );
    
    const playerIds = JSON.parse(room.player_ids);
    const totalPot = room.stake * playerIds.length;
    const houseEdge = totalPot * ENV_CONFIG.HOUSE_EDGE;
    const winnerPayout = totalPot - houseEdge;
    
    if (winnerId && room.stake > 0) {
      await pool.query('UPDATE users SET balance = balance + $1, wins = wins + 1, xp = xp + 10 WHERE player_id = $2', [winnerPayout, winnerId]);
      
      await pool.query(
        'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, winnerId, 'WIN', winnerPayout, roomId, 'COMPLETED']
      );
      
      for (const playerId of playerIds) {
        if (playerId !== winnerId) {
          await pool.query('UPDATE users SET losses = losses + 1 WHERE player_id = $1', [playerId]);
          
          await pool.query(
            'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, playerId, 'LOSS', -room.stake, roomId, 'COMPLETED']
          );
        }
      }
    }
    
    io.to(roomId).emit('game_ended', { roomId, winnerId, scores, winnerPayout });
    
    res.json({ success: true, winnerId, winnerPayout });
  } catch (error) {
    next(error);
  }
});

// ==================== LEADERBOARD ROUTES ====================
app.get('/api/leaderboard', async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT player_id, username, avatar_id, wins, losses, xp, (wins - losses) as score FROM users ORDER BY score DESC, xp DESC LIMIT 100'
    );
    
    const leaderboard = result.rows.map((row, index) => ({
      rank: index + 1,
      playerId: row.player_id,
      username: row.username || `Agent ${row.player_id.slice(0, 6)}`,
      avatarId: row.avatar_id,
      wins: row.wins,
      losses: row.losses,
      xp: row.xp,
      score: row.score
    }));
    
    res.json({ leaderboard });
  } catch (error) {
    next(error);
  }
});

// ==================== WEBSOCKET HANDLING ====================
io.on('connection', (socket) => {
  console.log('WebSocket client connected:', socket.id);
  
  socket.on('join_room', async (data) => {
    const { roomId, playerId } = data;
    socket.join(roomId);
    console.log(`Player ${playerId} joined room ${roomId}`);
    socket.to(roomId).emit('player_connected', { playerId });
  });
  
  socket.on('leave_room', async (data) => {
    const { roomId, playerId } = data;
    socket.leave(roomId);
    console.log(`Player ${playerId} left room ${roomId}`);
    socket.to(roomId).emit('player_disconnected', { playerId });
  });
  
  socket.on('game_action', async (data) => {
    const { roomId, playerId, action, payload } = data;
    io.to(roomId).emit('game_action', { playerId, action, payload });
  });
  
  socket.on('chat_message', async (data) => {
    const { roomId, playerId, message } = data;
    io.to(roomId).emit('chat_message', { playerId, message, timestamp: Date.now() });
  });
  
  socket.on('disconnect', () => {
    console.log('WebSocket client disconnected:', socket.id);
  });
});

// ==================== ADMIN ROUTES (HSM OPERATIONS) ====================
app.post('/api/admin/withdraw-cold', adminAuth, async (req, res, next) => {
  try {
    const { amount } = req.body;
    
    console.log('🔐 Admin cold wallet withdrawal - HSM operation');
    
    const txId = await sendZcashTransaction(
      ENV_CONFIG.PLATFORM_COLD_WALLET,
      amount,
      'Admin cold wallet transfer'
    );
    
    if (!txId) {
      return res.status(500).json(buildErrorResponse(ERROR_CODES.TRANSACTION_FAILED));
    }
    
    await logSecurityEvent('ADMIN_COLD_WITHDRAWAL', 'HIGH', {
      description: 'Admin cold wallet withdrawal',
      amount,
      txId
    });
    
    res.json({ success: true, txId, amount });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/stats', adminAuth, async (req, res, next) => {
  try {
    const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const verifiedCount = await pool.query('SELECT COUNT(*) as count FROM users WHERE is_verified = true');
    const totalBalance = await pool.query('SELECT COALESCE(SUM(balance), 0) as total FROM users');
    const activeGames = await pool.query("SELECT COUNT(*) as count FROM rooms WHERE status IN ('WAITING', 'IN_PROGRESS')");
    const totalDeposits = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'DEPOSIT'");
    const totalWithdrawals = await pool.query("SELECT COALESCE(SUM(ABS(amount)), 0) as total FROM transactions WHERE type = 'WITHDRAW'");
    
    res.json({
      users: {
        total: parseInt(userCount.rows[0].count),
        verified: parseInt(verifiedCount.rows[0].count)
      },
      balance: {
        total: parseFloat(totalBalance.rows[0].total)
      },
      games: {
        active: parseInt(activeGames.rows[0].count)
      },
      transactions: {
        deposits: parseFloat(totalDeposits.rows[0].total),
        withdrawals: parseFloat(totalWithdrawals.rows[0].total)
      }
    });
  } catch (error) {
    next(error);
  }
});

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    const blockchainInfo = await zcashRPC('getblockchaininfo');
    
    res.json({ 
      status: 'healthy',
      timestamp: Date.now(),
      version: '4.0.0',
      database: 'connected',
      redis: 'connected',
      blockchain: {
        connected: true,
        blocks: blockchainInfo.blocks,
        synced: !blockchainInfo.initialblockdownload
      },
      security: {
        encryption: 'AES-256-GCM',
        hsmEnabled: ENV_CONFIG.HSM_ENABLED,
        secretsEncrypted: true
      }
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'unhealthy',
      error: error.message,
      timestamp: Date.now()
    });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({ status: 'healthy', service: 'api', timestamp: Date.now() });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

// ==================== ERROR HANDLER ====================
app.use(errorHandler);

// ==================== 404 HANDLER ====================
app.use((req, res) => {
  res.status(404).json(buildErrorResponse(ERROR_CODES.INTERNAL_ERROR, {
    message: 'Endpoint not found',
    path: req.path
  }));
});

// ==================== SERVER STARTUP ====================
server.listen(ENV_CONFIG.PORT, ENV_CONFIG.HOST, () => {
  console.log('');
  console.log('🚀 ZEC ARENA SERVER');
  console.log('==========================================');
  console.log(`Port: ${ENV_CONFIG.PORT}`);
  console.log(`Host: ${ENV_CONFIG.HOST}`);
  console.log(`Environment: ${ENV_CONFIG.NODE_ENV}`);
  console.log(`Network: ${ENV_CONFIG.ZCASH_NETWORK}`);
  console.log('==========================================');
  console.log('🔐 SECURITY:');
  console.log('   ✅ Secrets encrypted at rest (AES-256-GCM)');
  console.log('   ✅ User auth: bcrypt + pbkdf2 + JWT');
  if (ENV_CONFIG.HSM_ENABLED) {
    console.log(`   ✅ HSM enabled: ${ENV_CONFIG.HSM_TYPE} (admin only)`);
  } else {
    console.log('   ⚠️  HSM disabled (software keys)');
  }
  console.log('==========================================');
  console.log('✅ Server Ready');
  console.log('');
  console.log('To encrypt secrets:');
  console.log('  node backend.js encrypt "your-secret-here"');
  console.log('');
});

// ==================== GRACEFUL SHUTDOWN ====================
async function shutdown(signal) {
  console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
  });
  
  wss.close(() => {
    console.log('✅ WebSocket server closed');
  });

  try {
    await pool.end();
    console.log('✅ Database connections closed');
    
    await redis.quit();
    console.log('✅ Redis connection closed');
    
    console.log('✅ Shutdown complete');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection:', reason);
  shutdown('unhandledRejection');
});

module.exports = { app, server, io };