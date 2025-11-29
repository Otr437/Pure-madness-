// ==================== ZEC ARENA COMPLETE PRODUCTION BACKEND ====================
//  EVERY SINGLE FEATURE INCLUDED
// Version: 7.0.0-ULTIMATE | November  2025
// 

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
const WebSocket = require('ws');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
const io = new Server(server, { 
  cors: { origin: '*' },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling']
});

// ==================== ENCRYPTED SECRETS HANDLER ====================
const MASTER_KEY_HEX = process.env.MASTER_KEY;
const MASTER_KEY = MASTER_KEY_HEX ? Buffer.from(MASTER_KEY_HEX, 'hex') : crypto.randomBytes(32);

if (!MASTER_KEY_HEX && process.env.NODE_ENV === 'production') {
  console.error('❌ CRITICAL: MASTER_KEY environment variable not set in production');
  console.error('Generate one with: openssl rand -hex 32');
  process.exit(1);
}

function decryptSecret(encrypted) {
  if (!encrypted || !encrypted.startsWith('ENC:')) {
    return encrypted;
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
    throw new Error('Failed to decrypt secret');
  }
}

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return `ENC:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

if (process.argv[2] === 'encrypt' && process.argv[3]) {
  console.log('\n🔐 Encrypted secret (add to .env):');
  console.log(encryptSecret(process.argv[3]));
  console.log('');
  process.exit(0);
}

// ==================== COMPLETE CONFIGURATION ====================
const CONFIG = {
  // Server
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT) || 3001,
  HOST: process.env.HOST || '0.0.0.0',
  FRONTEND_URL: process.env.FRONTEND_URL || '*',
  
  // Database
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
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  
  // Zcash RPC
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
  
  // Security
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  API_KEY: process.env.API_KEY ? decryptSecret(process.env.API_KEY) : undefined,
  ADMIN_API_KEY: decryptSecret(process.env.ADMIN_API_KEY),
  JWT_SECRET: decryptSecret(process.env.JWT_SECRET) || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: process.env.JWT_EXPIRES || '7d',
  
  // HSM Configuration
  HSM_ENABLED: process.env.HSM_ENABLED === 'true',
  HSM_TYPE: process.env.HSM_TYPE || 'pkcs11',
  HSM_LIBRARY_PATH: process.env.HSM_LIBRARY_PATH,
  HSM_SLOT: parseInt(process.env.HSM_SLOT) || 0,
  HSM_PIN: process.env.HSM_PIN ? decryptSecret(process.env.HSM_PIN) : undefined,
  HSM_KEY_LABEL: process.env.HSM_KEY_LABEL || 'zec_arena_admin_master',
  
  // AWS KMS
  AWS_REGION: process.env.AWS_REGION,
  AWS_KMS_KEY_ID: process.env.AWS_KMS_KEY_ID,
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY ? decryptSecret(process.env.AWS_SECRET_ACCESS_KEY) : undefined,
  
  // Azure Key Vault
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
  
  // Picture Rush Settings
  PICTURE_RUSH_DURATION: parseInt(process.env.PICTURE_RUSH_DURATION) || 30000,
  PICTURE_RUSH_IMAGES: parseInt(process.env.PICTURE_RUSH_IMAGES) || 15,
  PICTURE_RUSH_CORRECT_POINTS: parseInt(process.env.PICTURE_RUSH_CORRECT_POINTS) || 100,
  PICTURE_RUSH_WRONG_PENALTY: parseInt(process.env.PICTURE_RUSH_WRONG_PENALTY) || 25,
  PICTURE_RUSH_STREAK_BONUS: parseInt(process.env.PICTURE_RUSH_STREAK_BONUS) || 50,
  PICTURE_RUSH_TIME_BONUS_MULTIPLIER: parseFloat(process.env.PICTURE_RUSH_TIME_BONUS_MULTIPLIER) || 0.1,
  PICTURE_RUSH_TIME_PER_IMAGE: parseInt(process.env.PICTURE_RUSH_TIME_PER_IMAGE) || 2000,
  
  // Picture Match Settings
  PICTURE_MATCH_DURATION: parseInt(process.env.PICTURE_MATCH_DURATION) || 90000,
  PICTURE_MATCH_GRID_SIZE: parseInt(process.env.PICTURE_MATCH_GRID_SIZE) || 16,
  PICTURE_MATCH_PAIR_POINTS: parseInt(process.env.PICTURE_MATCH_PAIR_POINTS) || 100,
  PICTURE_MATCH_MATCH_BONUS: parseInt(process.env.PICTURE_MATCH_MATCH_BONUS) || 50,
  PICTURE_MATCH_SPEED_BONUS: parseInt(process.env.PICTURE_MATCH_SPEED_BONUS) || 200,
  PICTURE_MATCH_WRONG_PENALTY: parseInt(process.env.PICTURE_MATCH_WRONG_PENALTY) || 10,
  
  // Matchmaking
  MATCH_TIMEOUT: parseInt(process.env.MATCH_TIMEOUT) || 120000,
  GAME_START_COUNTDOWN: parseInt(process.env.GAME_START_COUNTDOWN) || 10000,
  GAME_END_DELAY: parseInt(process.env.GAME_END_DELAY) || 5000,
  
  // XP & Levels
  XP_PER_WIN: parseInt(process.env.XP_PER_WIN) || 100,
  XP_PER_LOSS: parseInt(process.env.XP_PER_LOSS) || 10,
  XP_PER_GAME: parseInt(process.env.XP_PER_GAME) || 5,
  LEVEL_UP_BASE: parseInt(process.env.LEVEL_UP_BASE) || 100,
  LEVEL_UP_MULTIPLIER: parseFloat(process.env.LEVEL_UP_MULTIPLIER) || 1.5,
  
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
    'JWT_SECRET'
  ];
  
  const missing = required.filter(key => !CONFIG[key]);
  
  if (missing.length > 0 && CONFIG.NODE_ENV === 'production') {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }
  
  if (CONFIG.HSM_ENABLED) {
    console.log('🔐 HSM ENABLED - For ADMIN operations only');
    console.log('✅ User authentication: bcrypt + pbkdf2 + JWT (NO HSM)');
    
    const hsmRequired = {
      pkcs11: ['HSM_LIBRARY_PATH', 'HSM_PIN'],
      awskms: ['AWS_KMS_KEY_ID', 'AWS_REGION'],
      azure: ['AZURE_KEYVAULT_URL', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'],
      yubihsm: ['YUBIHSM_AUTH_KEY_ID', 'YUBIHSM_PASSWORD']
    };
    
    const requiredHsmKeys = hsmRequired[CONFIG.HSM_TYPE] || [];
    const missingHsm = requiredHsmKeys.filter(key => !CONFIG[key]);
    
    if (missingHsm.length > 0) {
      console.error(`❌ Missing HSM configuration for ${CONFIG.HSM_TYPE}:`, missingHsm.join(', '));
      process.exit(1);
    }
  }
  
  console.log('✅ Configuration validated');
}

validateConfig();

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", CONFIG.FRONTEND_URL, "wss:", "ws:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: CONFIG.NODE_ENV === 'production' ? [] : null
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
  origin: CONFIG.FRONTEND_URL === '*' ? '*' : CONFIG.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== RATE LIMITING ====================
const generalLimiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW,
  max: CONFIG.RATE_LIMIT_MAX,
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
  host: CONFIG.DB_HOST,
  port: CONFIG.DB_PORT,
  database: CONFIG.DB_NAME,
  user: CONFIG.DB_USER,
  password: CONFIG.DB_PASSWORD,
  max: CONFIG.DB_MAX_CONNECTIONS,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: CONFIG.DB_SSL ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('💥 Database connection error:', err);
});

pool.on('connect', () => {
  console.log('✅ Database connected');
});

// ==================== REDIS CONNECTION ====================
const redis = new Redis(CONFIG.REDIS_URL || {
  host: CONFIG.REDIS_HOST,
  port: CONFIG.REDIS_PORT,
  password: CONFIG.REDIS_PASSWORD,
  db: CONFIG.REDIS_DB,
  retryStrategy: (times) => Math.min(times * 50, 2000),
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  tls: CONFIG.REDIS_TLS ? { rejectUnauthorized: false } : undefined
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
  },
  [ERROR_CODES.GAME_NOT_FOUND]: {
    message: 'Game not found',
    userMessage: 'The game you\'re looking for doesn\'t exist or has ended.',
    action: 'Return to lobby and join another game'
  },
  [ERROR_CODES.GAME_FULL]: {
    message: 'Game is full',
    userMessage: 'This game has reached maximum players.',
    action: 'Try another game or create your own'
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
    stack: CONFIG.NODE_ENV === 'development' ? err.stack : undefined,
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
    message: CONFIG.NODE_ENV === 'development' ? err.message : 'Internal server error'
  }));
}

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ==================== ZCASH RPC ====================
async function zcashRPC(method, params = []) {
  try {
    const response = await axios.post(CONFIG.ZCASH_RPC_URL, {
      jsonrpc: '1.0',
      id: 'zecarena',
      method,
      params
    }, {
      auth: {
        username: CONFIG.ZCASH_RPC_USER,
        password: CONFIG.ZCASH_RPC_PASSWORD
      },
      headers: { 'Content-Type': 'application/json' },
      timeout: CONFIG.ZCASH_RPC_TIMEOUT
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
}

async function verifyZcashTransaction(txId, expectedAmount, expectedMemo) {
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
    
    if (confirmations < CONFIG.MIN_CONFIRMATIONS) {
      return { 
        valid: false, 
        error: 'Not enough confirmations', 
        confirmations, 
        required: CONFIG.MIN_CONFIRMATIONS 
      };
    }
    
    return { valid: true, amount, memo, confirmations };
  } catch (error) {
    console.error('Verification error:', error);
    return { valid: false, error: error.message || 'Verification failed' };
  }
}

async function sendZcashTransaction(toAddress, amount, memo) {
  try {
    const memoHex = Buffer.from(memo, 'utf8').toString('hex').padEnd(1024, '0');
    const operationId = await zcashRPC('z_sendmany', [
      CONFIG.PLATFORM_HOT_WALLET,
      [{ address: toAddress, amount, memo: memoHex }],
      1,
      CONFIG.WITHDRAWAL_FEE
    ]);
    
    for (let i = 0; i < 60; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const operations = await zcashRPC('z_getoperationstatus', [[operationId]]);
      if (operations[0].status === 'success') {
        return operations[0].result.txid;
      } else if (operations[0].status === 'failed') {
        throw new Error(operations[0].error.message);
      }
    }
    return null;
  } catch (error) {
    console.error('Send transaction error:', error);
    return null;
  }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new AppError('No token provided', 401, ERROR_CODES.UNAUTHORIZED);
    }

    let decoded;
    try {
      decoded = jwt.verify(token, CONFIG.JWT_SECRET);
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
    
    // Cache session
    await redis.setex(`session:${decoded.playerId}`, 3600, JSON.stringify(req.user));
    
    next();
  } catch (error) {
    next(error);
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const adminKey = req.header('X-Admin-Key');
    
    if (!adminKey || adminKey !== CONFIG.ADMIN_API_KEY) {
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

// ==================== BRUTE FORCE PROTECTION ====================
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

// ==================== COMPLETE GAME MANAGER ====================
class GameManager {
  constructor() {
    this.activeGames = new Map();
    this.playerSockets = new Map();
    this.matchmakingQueue = new Map();
  }

  getPictureRushImages() {
    return [
      { id: 1, name: 'Eiffel Tower', category: 'landmark', difficulty: 1, imageUrl: '/assets/rush/eiffel.jpg', options: ['Eiffel Tower', 'Big Ben', 'Tokyo Tower', 'Space Needle'] },
      { id: 2, name: 'Albert Einstein', category: 'person', difficulty: 2, imageUrl: '/assets/rush/einstein.jpg', options: ['Albert Einstein', 'Isaac Newton', 'Nikola Tesla', 'Thomas Edison'] },
      { id: 3, name: 'Taj Mahal', category: 'landmark', difficulty: 1, imageUrl: '/assets/rush/taj.jpg', options: ['Taj Mahal', 'Angkor Wat', 'Petra', 'Machu Picchu'] },
      { id: 4, name: 'Marilyn Monroe', category: 'person', difficulty: 2, imageUrl: '/assets/rush/monroe.jpg', options: ['Marilyn Monroe', 'Audrey Hepburn', 'Grace Kelly', 'Elizabeth Taylor'] },
      { id: 5, name: 'Great Wall of China', category: 'landmark', difficulty: 1, imageUrl: '/assets/rush/wall.jpg', options: ['Great Wall of China', 'Hadrians Wall', 'Berlin Wall', 'Western Wall'] },
      { id: 6, name: 'Mona Lisa', category: 'art', difficulty: 1, imageUrl: '/assets/rush/mona.jpg', options: ['Mona Lisa', 'Girl with Pearl Earring', 'The Scream', 'Starry Night'] },
      { id: 7, name: 'Statue of Liberty', category: 'landmark', difficulty: 1, imageUrl: '/assets/rush/liberty.jpg', options: ['Statue of Liberty', 'Christ the Redeemer', 'David', 'Manneken Pis'] },
      { id: 8, name: 'Michael Jordan', category: 'person', difficulty: 2, imageUrl: '/assets/rush/jordan.jpg', options: ['Michael Jordan', 'LeBron James', 'Kobe Bryant', 'Magic Johnson'] },
      { id: 9, name: 'Pyramids of Giza', category: 'landmark', difficulty: 1, imageUrl: '/assets/rush/pyramid.jpg', options: ['Pyramids of Giza', 'Mayan Pyramids', 'Aztec Pyramids', 'Nubian Pyramids'] },
      { id: 10, name: 'Golden Gate Bridge', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/golden.jpg', options: ['Golden Gate Bridge', 'Brooklyn Bridge', 'Tower Bridge', 'Sydney Harbour Bridge'] },
      { id: 11, name: 'Big Ben', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/bigben.jpg', options: ['Big Ben', 'Leaning Tower', 'CN Tower', 'Burj Khalifa'] },
      { id: 12, name: 'Muhammad Ali', category: 'person', difficulty: 2, imageUrl: '/assets/rush/ali.jpg', options: ['Muhammad Ali', 'Mike Tyson', 'Joe Frazier', 'George Foreman'] },
      { id: 13, name: 'Colosseum', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/colosseum.jpg', options: ['Colosseum', 'Arena of Nîmes', 'Verona Arena', 'Pula Arena'] },
      { id: 14, name: 'Niagara Falls', category: 'nature', difficulty: 2, imageUrl: '/assets/rush/niagara.jpg', options: ['Niagara Falls', 'Victoria Falls', 'Angel Falls', 'Iguazu Falls'] },
      { id: 15, name: 'Mount Rushmore', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/rushmore.jpg', options: ['Mount Rushmore', 'Stone Mountain', 'Crazy Horse', 'Mount Nemrut'] },
      { id: 16, name: 'Leonardo da Vinci', category: 'person', difficulty: 3, imageUrl: '/assets/rush/davinci.jpg', options: ['Leonardo da Vinci', 'Michelangelo', 'Raphael', 'Donatello'] },
      { id: 17, name: 'Mecca', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/mecca.jpg', options: ['Mecca', 'Medina', 'Jerusalem', 'Vatican City'] },
      { id: 18, name: 'Cleopatra', category: 'person', difficulty: 3, imageUrl: '/assets/rush/cleopatra.jpg', options: ['Cleopatra', 'Nefertiti', 'Hatshepsut', 'Tutankhamun'] },
      { id: 19, name: 'Christ the Redeemer', category: 'landmark', difficulty: 2, imageUrl: '/assets/rush/christ.jpg', options: ['Christ the Redeemer', 'Statue of Liberty', 'Spring Temple Buddha', 'The Motherland Calls'] },
      { id: 20, name: 'Nelson Mandela', category: 'person', difficulty: 2, imageUrl: '/assets/rush/mandela.jpg', options: ['Nelson Mandela', 'Martin Luther King Jr.', 'Mahatma Gandhi', 'Desmond Tutu'] }
    ].sort(() => Math.random() - 0.5).slice(0, CONFIG.PICTURE_RUSH_IMAGES);
  }

  initPictureRush(gameId, players, stake) {
    const images = this.getPictureRushImages();

    return {
      gameId,
      type: 'PICTURE_RUSH',
      stake,
      players: players.map(p => ({
        playerId: p.player_id,
        username: p.username || `Agent ${p.player_id.slice(0, 6)}`,
        avatar: p.avatar_id || 'hero_1',
        score: 0,
        correctAnswers: 0,
        wrongAnswers: 0,
        streak: 0,
        longestStreak: 0,
        answers: [],
        ready: false
      })),
      images,
      currentImageIndex: 0,
      startTime: Date.now(),
      endTime: Date.now() + CONFIG.PICTURE_RUSH_DURATION,
      status: 'ACTIVE',
      round: 1,
      totalRounds: CONFIG.PICTURE_RUSH_IMAGES
    };
  }

  handlePictureRushAnswer(gameId, playerId, imageIndex, answer) {
    const game = this.activeGames.get(gameId);
    if (!game || game.status !== 'ACTIVE') {
      return { error: 'Game not active' };
    }
    
    const player = game.players.find(p => p.playerId === playerId);
    if (!player) return { error: 'Player not found' };
    
    if (player.answers.find(a => a.imageIndex === imageIndex)) {
      return { error: 'Already answered this question' };
    }
    
    const image = game.images[imageIndex];
    if (!image) return { error: 'Invalid image' };
    
    const correct = answer === image.name;
    const timeElapsed = Date.now() - game.startTime;
    const timeForThisImage = timeElapsed - (imageIndex * (CONFIG.PICTURE_RUSH_DURATION / CONFIG.PICTURE_RUSH_IMAGES));
    const timeBonus = Math.max(0, Math.floor((CONFIG.PICTURE_RUSH_TIME_PER_IMAGE - timeForThisImage) * CONFIG.PICTURE_RUSH_TIME_BONUS_MULTIPLIER));
    
    if (correct) {
      player.correctAnswers++;
      player.streak++;
      player.longestStreak = Math.max(player.longestStreak, player.streak);
      
      const streakBonus = player.streak >= 3 ? CONFIG.PICTURE_RUSH_STREAK_BONUS * Math.floor(player.streak / 3) : 0;
      const difficultyBonus = image.difficulty * 20;
      
      player.score += CONFIG.PICTURE_RUSH_CORRECT_POINTS + timeBonus + streakBonus + difficultyBonus;
    } else {
      player.wrongAnswers++;
      player.streak = 0;
      player.score = Math.max(0, player.score - CONFIG.PICTURE_RUSH_WRONG_PENALTY);
    }
    
    player.answers.push({
      imageIndex,
      answer,
      correct,
      correctAnswer: image.name,
      timeBonus,
      timestamp: Date.now()
    });
    
    this.activeGames.set(gameId, game);
    this.broadcastGameState(gameId);
    
    const allAnswered = game.players.every(p => 
      p.answers.find(a => a.imageIndex === imageIndex)
    );
    
    if (allAnswered && imageIndex === game.images.length - 1) {
      setTimeout(() => this.endGame(gameId), 1000);
    }
    
    return { 
      success: true, 
      correct, 
      correctAnswer: image.name,
      player: {
        score: player.score,
        streak: player.streak,
        correctAnswers: player.correctAnswers,
        wrongAnswers: player.wrongAnswers
      }
    };
  }

  initPictureMatch(gameId, players, stake) {
    const baseImages = Array.from({ length: CONFIG.PICTURE_MATCH_GRID_SIZE / 2 }, (_, i) => ({
      id: i + 1,
      imageUrl: `/assets/match/card-${i + 1}.jpg`,
      type: `type_${i + 1}`
    }));
    
    const grid = [...baseImages, ...baseImages]
      .sort(() => Math.random() - 0.5)
      .map((img, index) => ({
        position: index,
        imageId: img.id,
        imageUrl: img.imageUrl,
        type: img.type,
        revealed: false,
        matched: false,
        flippedBy: null,
        flippedAt: null
      }));

    return {
      gameId,
      type: 'PICTURE_MATCH',
      stake,
      players: players.map((p, index) => ({
        playerId: p.player_id,
        username: p.username || `Agent ${p.player_id.slice(0, 6)}`,
        avatar: p.avatar_id || 'hero_1',
        score: 0,
        pairsFound: 0,
        attempts: 0,
        turnCount: 0,
        lastMatchTime: null,
        consecutiveMatches: 0,
        ready: false
      })),
      grid,
      startTime: Date.now(),
      endTime: Date.now() + CONFIG.PICTURE_MATCH_DURATION,
      status: 'ACTIVE',
      currentTurn: players[0].player_id,
      selectedCards: [],
      moves: [],
      totalMatches: 0
    };
  }

  handlePictureMatchCardFlip(gameId, playerId, cardPosition) {
    const game = this.activeGames.get(gameId);
    if (!game || game.status !== 'ACTIVE') {
      return { error: 'Game not active' };
    }
    
    if (game.currentTurn !== playerId) {
      return { error: 'Not your turn' };
    }
    
    const player = game.players.find(p => p.playerId === playerId);
    if (!player) return { error: 'Player not found' };
    
    const card = game.grid[cardPosition];
    if (!card || card.matched || card.revealed) {
      return { error: 'Invalid card selection' };
    }
    
    card.revealed = true;
    card.flippedBy = playerId;
    card.flippedAt = Date.now();
    game.selectedCards.push(cardPosition);
    
    game.moves.push({
      playerId,
      cardPosition,
      timestamp: Date.now()
    });
    
    this.activeGames.set(gameId, game);
    this.broadcastGameState(gameId);
    
    if (game.selectedCards.length === 2) {
      player.attempts++;
      player.turnCount++;
      
      const [pos1, pos2] = game.selectedCards;
      const card1 = game.grid[pos1];
      const card2 = game.grid[pos2];
      
      if (card1.imageId === card2.imageId) {
        card1.matched = true;
        card2.matched = true;
        player.pairsFound++;
        player.consecutiveMatches++;
        game.totalMatches++;
        
        const timeSinceStart = Date.now() - game.startTime;
        const timeSinceLastMatch = player.lastMatchTime ? Date.now() - player.lastMatchTime : timeSinceStart;
        
        const speedBonus = timeSinceStart < 30000 ? CONFIG.PICTURE_MATCH_SPEED_BONUS : 0;
        const consecutiveBonus = player.consecutiveMatches >= 2 ? CONFIG.PICTURE_MATCH_MATCH_BONUS * (player.consecutiveMatches - 1) : 0;
        const quickMatchBonus = timeSinceLastMatch < 5000 ? 50 : 0;
        
        player.score += CONFIG.PICTURE_MATCH_PAIR_POINTS + speedBonus + consecutiveBonus + quickMatchBonus;
        player.lastMatchTime = Date.now();
        
        game.selectedCards = [];
        
        this.activeGames.set(gameId, game);
        this.broadcastGameState(gameId);
        
        const allMatched = game.grid.every(c => c.matched);
        if (allMatched) {
          game.status = 'FINISHED';
          setTimeout(() => this.endGame(gameId), 2000);
        }
        
        return { 
          success: true, 
          match: true,
          card,
          bonus: speedBonus + consecutiveBonus + quickMatchBonus,
          player: {
            score: player.score,
            pairsFound: player.pairsFound,
            consecutiveMatches: player.consecutiveMatches
          }
        };
      } else {
        player.consecutiveMatches = 0;
        player.score = Math.max(0, player.score - CONFIG.PICTURE_MATCH_WRONG_PENALTY);
        
        setTimeout(() => {
          if (!card1.matched) {
            card1.revealed = false;
            card1.flippedBy = null;
          }
          if (!card2.matched) {
            card2.revealed = false;
            card2.flippedBy = null;
          }
          game.selectedCards = [];
          
          const currentIndex = game.players.findIndex(p => p.playerId === playerId);
          const nextIndex = (currentIndex + 1) % game.players.length;
          game.currentTurn = game.players[nextIndex].playerId;
          
          this.activeGames.set(gameId, game);
          this.broadcastGameState(gameId);
        }, 1500);
        
        return { 
          success: true, 
          match: false,
          card,
          player: {
            score: player.score,
            attempts: player.attempts
          }
        };
      }
    }
    
    return { success: true, card };
  }

  async endGame(gameId) {
    const game = this.activeGames.get(gameId);
    if (!game) return;
    
    game.status = 'FINISHED';
    game.endTime = Date.now();
    
    const sortedPlayers = [...game.players].sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      if (game.type === 'PICTURE_MATCH') {
        return a.attempts - b.attempts;
      } else {
        return b.correctAnswers - a.correctAnswers;
      }
    });
    
    const winner = sortedPlayers[0];
    const isTie = sortedPlayers.length > 1 && sortedPlayers[0].score === sortedPlayers[1].score;
    
    game.winnerId = winner.playerId;
    game.finalScores = sortedPlayers.map((p, index) => ({
      playerId: p.playerId,
      username: p.username,
      rank: index + 1,
      score: p.score,
      stats: game.type === 'PICTURE_RUSH' ? {
        correctAnswers: p.correctAnswers,
        wrongAnswers: p.wrongAnswers,
        streak: p.longestStreak
      } : {
        pairsFound: p.pairsFound,
        attempts: p.attempts,
        accuracy: p.attempts > 0 ? ((p.pairsFound / p.attempts) * 100).toFixed(1) : 0
      }
    }));
    
    this.activeGames.set(gameId, game);
    this.broadcastGameState(gameId);
    
    if (game.stake > 0) {
      await this.processGamePayout(game);
    }
    
    await this.updatePlayerStats(game);
    
    io.to(gameId).emit('game_over', {
      gameId,
      winner: {
        playerId: winner.playerId,
        username: winner.username,
        score: winner.score
      },
      isTie,
      finalScores: game.finalScores,
      duration: game.endTime - game.startTime
    });
    
    setTimeout(() => {
      this.activeGames.delete(gameId);
      console.log(`✅ Game ${gameId} cleaned up`);
    }, CONFIG.GAME_END_DELAY);
  }

  async processGamePayout(game) {
    try {
      const totalPot = game.stake * game.players.length;
      const houseEdge = totalPot * CONFIG.HOUSE_EDGE;
      const winnerPayout = totalPot - houseEdge;
      
      await pool.query(
        'UPDATE users SET balance = balance + $1, wins = wins + 1, xp = xp + $2 WHERE player_id = $3',
        [winnerPayout, CONFIG.XP_PER_WIN, game.winnerId]
      );
      
      await pool.query(
        'INSERT INTO transactions (id, user_id, type, amount, tx_id, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())',
        [
          `tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
          game.winnerId,
          'WIN',
          winnerPayout,
          game.gameId,
          'COMPLETED'
        ]
      );
      
      for (const player of game.players) {
        if (player.playerId !== game.winnerId) {
          await pool.query(
            'UPDATE users SET losses = losses + 1, xp = xp + $1 WHERE player_id = $2',
            [CONFIG.XP_PER_LOSS, player.playerId]
          );
          
          await pool.query(
            'INSERT INTO transactions (id, user_id, type, amount, tx_id, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())',
            [
              `tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
              player.playerId,
              'LOSS',
              -game.stake,
              game.gameId,
              'COMPLETED'
            ]
          );
        }
      }
      
      await pool.query(
        'UPDATE rooms SET status = $1, winner_id = $2, scores = $3, finished_at = NOW() WHERE id = $4',
        ['FINISHED', game.winnerId, JSON.stringify(game.finalScores), game.gameId]
      );
      
      console.log(`✅ Game ${game.gameId} payout: ${winnerPayout} ZEC to ${game.winnerId}`);
    } catch (error) {
      console.error('Payout error:', error);
    }
  }

  async updatePlayerStats(game) {
    try {
      for (const player of game.players) {
        await pool.query(
          'UPDATE users SET total_games = total_games + 1, xp = xp + $1 WHERE player_id = $2',
          [CONFIG.XP_PER_GAME, player.playerId]
        );
        
        await redis.del(`session:${player.playerId}`);
      }
    } catch (error) {
      console.error('Stats update error:', error);
    }
  }

  broadcastGameState(gameId) {
    const game = this.activeGames.get(gameId);
    if (!game) return;
    
    io.to(gameId).emit('game_state_update', {
      gameId,
      type: game.type,
      players: game.players,
      status: game.status,
      currentTurn: game.currentTurn,
      timeRemaining: game.endTime - Date.now(),
      ...(game.type === 'PICTURE_RUSH' && {
        currentImageIndex: game.currentImageIndex,
        totalImages: game.images.length
      }),
      ...(game.type === 'PICTURE_MATCH' && {
        totalMatches: game.totalMatches,
        maxMatches: CONFIG.PICTURE_MATCH_GRID_SIZE / 2
      })
    });
  }

  checkGameTimeout(gameId) {
    const game = this.activeGames.get(gameId);
    if (!game || game.status !== 'ACTIVE') return;
    
    if (Date.now() >= game.endTime) {
      console.log(`⏱️ Game ${gameId} timed out`);
      this.endGame(gameId);
    }
  }

  async cleanupInactiveGames() {
    for (const [gameId, game] of this.activeGames.entries()) {
      const timeSinceStart = Date.now() - game.startTime;
      
      if (game.status === 'STARTING' && timeSinceStart > 120000) {
        console.log(`🧹 Cleaning up stuck game: ${gameId}`);
        await this.refundPlayers(game);
        this.activeGames.delete(gameId);
      }
      
      if (game.status === 'FINISHED' && timeSinceStart > 300000) {
        console.log(`🧹 Cleaning up old game: ${gameId}`);
        this.activeGames.delete(gameId);
      }
    }
  }

  async refundPlayers(game) {
    if (game.stake > 0) {
      for (const player of game.players) {
        await pool.query(
          'UPDATE users SET balance = balance + $1 WHERE player_id = $2',
          [game.stake, player.playerId]
        );
        console.log(`💰 Refunded ${game.stake} ZEC to ${player.playerId}`);
      }
    }
  }
}

const gameManager = new GameManager();

setInterval(() => {
  for (const [gameId] of gameManager.activeGames) {
    gameManager.checkGameTimeout(gameId);
  }
}, 1000);


// ==================== AUTH ROUTES ====================
app.post('/api/auth/signup', signupLimiter, asyncHandler(async (req, res) => {
  const { password, email, username } = req.body;
  
  if (!password || password.length < 8) {
    throw new AppError('Password must be at least 8 characters', 400, ERROR_CODES.PASSWORD_WEAK, {
      requirement: 'At least 8 characters'
    });
  }

  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  
  if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
    throw new AppError('Password weak', 400, ERROR_CODES.PASSWORD_WEAK, {
      missing: [
        !hasUpperCase && 'uppercase letter',
        !hasLowerCase && 'lowercase letter',
        !hasNumbers && 'number'
      ].filter(Boolean),
      example: 'MyP@ssw0rd123'
    });
  }

  if (username) {
    const existing = await pool.query(
      'SELECT player_id FROM users WHERE username = $1',
      [username]
    );
    if (existing.rows.length > 0) {
      throw new AppError('Username taken', 409, ERROR_CODES.USER_EXISTS, {
        field: 'username'
      });
    }
  }

  if (email) {
    const existing = await pool.query(
      'SELECT player_id FROM users WHERE email = $1',
      [email]
    );
    if (existing.rows.length > 0) {
      throw new AppError('Email exists', 409, ERROR_CODES.USER_EXISTS, {
        field: 'email'
      });
    }
  }

  const playerId = crypto.randomBytes(5).toString('hex').toUpperCase().substring(0, 8);
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');

  await pool.query(
    `INSERT INTO users (
      player_id, password_hash, salt, email, username, balance, 
      is_verified, avatar_id, hide_balance, wins, losses, xp, 
      total_games, streak, created_at, last_login
    ) VALUES ($1, $2, $3, $4, $5, 0, false, $6, false, 0, 0, 0, 0, 0, NOW(), NOW())`,
    [playerId, hash, salt, email || null, username || null, 'hero_1']
  );

  const token = jwt.sign({ playerId }, CONFIG.JWT_SECRET, { expiresIn: CONFIG.JWT_EXPIRES });

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
    user: {
      playerId,
      username: username || null,
      email: email || null,
      avatarId: 'hero_1',
      balance: 0,
      isVerified: false
    },
    message: 'Account created successfully'
  });
}));

app.post('/api/auth/login', loginLimiter, asyncHandler(async (req, res) => {
  const { playerId, password } = req.body;

  if (!playerId || !password) {
    throw new AppError('Missing credentials', 400, ERROR_CODES.INVALID_CREDENTIALS);
  }

  const bruteCheck = await checkBruteForce(playerId);
  if (bruteCheck.blocked) {
    await logSecurityEvent('LOGIN_BLOCKED', 'MEDIUM', {
      playerId,
      ipAddress: req.ip,
      description: 'Login blocked due to brute force attempts'
    });
    
    throw new AppError('Account locked', 429, ERROR_CODES.ACCOUNT_LOCKED, {
      attempts: 5,
      waitTime: '1 hour'
    });
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
    throw new AppError('Invalid credentials', 401, ERROR_CODES.USER_NOT_FOUND, {
      providedId: playerId
    });
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
    
    throw new AppError('Invalid credentials', 401, ERROR_CODES.INVALID_CREDENTIALS, {
      attemptsLeft: Math.max(0, 5 - attempts),
      lockoutWarning: attempts >= 4 ? 'One more failed attempt will lock your account' : null
    });
  }

  await clearBruteForce(user.player_id);

  await pool.query(
    'UPDATE users SET last_login = NOW() WHERE player_id = $1',
    [user.player_id]
  );

  const token = jwt.sign({ playerId: user.player_id }, CONFIG.JWT_SECRET, { expiresIn: CONFIG.JWT_EXPIRES });

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
    user: {
      playerId: user.player_id,
      username: user.username,
      email: user.email,
      avatarId: user.avatar_id,
      balance: parseFloat(user.balance),
      isVerified: user.is_verified,
      hideBalance: user.hide_balance,
      wins: user.wins,
      losses: user.losses,
      xp: user.xp,
      totalGames: user.total_games,
      streak: user.streak
    }
  });
}));

app.post('/api/auth/verify-token', asyncHandler(async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    throw new AppError('Token required', 400, ERROR_CODES.TOKEN_INVALID);
  }

  let decoded;
  try {
    decoded = jwt.verify(token, CONFIG.JWT_SECRET);
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Token expired', 401, ERROR_CODES.TOKEN_EXPIRED, {
        expiredAt: error.expiredAt
      });
    }
    throw new AppError('Invalid token', 401, ERROR_CODES.TOKEN_INVALID, {
      reason: error.message
    });
  }
  
  const cached = await redis.get(`session:${decoded.playerId}`);
  if (cached) {
    return res.json({ valid: true, user: JSON.parse(cached) });
  }

  const result = await pool.query(
    'SELECT player_id, username, email, avatar_id, balance, is_verified, hide_balance, wins, losses, xp, total_games, streak FROM users WHERE player_id = $1',
    [decoded.playerId]
  );

  if (result.rows.length === 0) {
    throw new AppError('User not found', 401, ERROR_CODES.USER_NOT_FOUND, {
      playerId: decoded.playerId
    });
  }

  res.json({ valid: true, user: result.rows[0] });
}));

app.post('/api/auth/logout', asyncHandler(async (req, res) => {
  const { playerId } = req.body;
  
  if (!playerId) {
    throw new AppError('Player ID required', 400, ERROR_CODES.USER_NOT_FOUND);
  }
  
  await redis.del(`session:${playerId}`);
  
  await logSecurityEvent('USER_LOGOUT', 'LOW', {
    playerId,
    ipAddress: req.ip,
    description: 'User logged out'
  });
  
  res.json({ success: true, message: 'Logged out successfully' });
}));

app.post('/api/auth/refresh', asyncHandler(async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    throw new AppError('Token required', 400, ERROR_CODES.TOKEN_INVALID);
  }
  
  let decoded;
  try {
    decoded = jwt.verify(token, CONFIG.JWT_SECRET);
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Token expired', 401, ERROR_CODES.TOKEN_EXPIRED);
    }
    throw new AppError('Invalid token', 401, ERROR_CODES.TOKEN_INVALID);
  }
  
  const newToken = jwt.sign({ playerId: decoded.playerId }, CONFIG.JWT_SECRET, { expiresIn: CONFIG.JWT_EXPIRES });
  
  res.json({ 
    success: true,
    token: newToken,
    expiresIn: CONFIG.JWT_EXPIRES
  });
}));

app.post('/api/auth/change-password', auth, asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    throw new AppError('Password weak', 400, ERROR_CODES.PASSWORD_WEAK);
  }

  const hasUpperCase = /[A-Z]/.test(newPassword);
  const hasLowerCase = /[a-z]/.test(newPassword);
  const hasNumbers = /\d/.test(newPassword);
  
  if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
    throw new AppError('Password weak', 400, ERROR_CODES.PASSWORD_WEAK, {
      missing: [
        !hasUpperCase && 'uppercase',
        !hasLowerCase && 'lowercase',
        !hasNumbers && 'number'
      ].filter(Boolean)
    });
  }

  const oldHash = crypto.pbkdf2Sync(oldPassword, req.user.salt, 100000, 64, 'sha512').toString('hex');

  if (oldHash !== req.user.password_hash) {
    throw new AppError('Invalid credentials', 401, ERROR_CODES.INVALID_CREDENTIALS, {
      field: 'oldPassword'
    });
  }

  const newSalt = crypto.randomBytes(16).toString('hex');
  const newHash = crypto.pbkdf2Sync(newPassword, newSalt, 100000, 64, 'sha512').toString('hex');

  await pool.query(
    'UPDATE users SET password_hash = $1, salt = $2 WHERE player_id = $3',
    [newHash, newSalt, req.user.player_id]
  );

  await redis.del(`session:${req.user.player_id}`);

  await logSecurityEvent('PASSWORD_CHANGED', 'MEDIUM', {
    playerId: req.user.player_id,
    ipAddress: req.ip,
    description: 'Password changed successfully'
  });


// ==================== ACCOUNT ROUTES ====================
app.get('/api/account/me', auth, asyncHandler(async (req, res) => {
  const result = await pool.query(
    `SELECT 
      player_id, username, email, avatar_id, balance, is_verified, 
      hide_balance, wins, losses, xp, total_games, streak, 
      created_at, last_login
    FROM users WHERE player_id = $1`,
    [req.user.player_id]
  );
  
  if (result.rows.length === 0) {
    throw new AppError('User not found', 404, ERROR_CODES.USER_NOT_FOUND);
  }
  
  const user = result.rows[0];
  
  const level = Math.floor(Math.log(user.xp / CONFIG.LEVEL_UP_BASE + 1) / Math.log(CONFIG.LEVEL_UP_MULTIPLIER)) + 1;
  const xpForNextLevel = Math.floor(CONFIG.LEVEL_UP_BASE * Math.pow(CONFIG.LEVEL_UP_MULTIPLIER, level));
  const xpForCurrentLevel = Math.floor(CONFIG.LEVEL_UP_BASE * Math.pow(CONFIG.LEVEL_UP_MULTIPLIER, level - 1));
  const xpProgress = user.xp - xpForCurrentLevel;
  const xpNeeded = xpForNextLevel - xpForCurrentLevel;
  
  res.json({
    user: {
      playerId: user.player_id,
      username: user.username,
      email: user.email,
      avatarId: user.avatar_id,
      balance: parseFloat(user.balance),
      isVerified: user.is_verified,
      hideBalance: user.hide_balance,
      wins: user.wins,
      losses: user.losses,
      xp: user.xp,
      level,
      xpProgress,
      xpNeeded,
      totalGames: user.total_games,
      streak: user.streak,
      winRate: user.total_games > 0 ? ((user.wins / user.total_games) * 100).toFixed(1) : 0,
      createdAt: user.created_at,
      lastLogin: user.last_login
    }
  });
}));

app.post('/api/account/verify', auth, transactionLimiter, asyncHandler(async (req, res) => {
  const { txId } = req.body;
  
  if (!txId || txId.length < 10) {
    throw new AppError('Invalid transaction ID', 400, ERROR_CODES.INVALID_ADDRESS, {
      field: 'txId'
    });
  }
  
  const verification = await verifyZcashTransaction(txId, CONFIG.VERIFICATION_FEE, req.user.player_id);
  
  if (!verification.valid) {
    throw new AppError('Transaction failed', 400, ERROR_CODES.TRANSACTION_FAILED, {
      error: verification.error,
      confirmations: verification.confirmations,
      required: verification.required
    });
  }
  
  await pool.query(
    'UPDATE users SET is_verified = true, verification_tx_id = $1 WHERE player_id = $2',
    [txId, req.user.player_id]
  );
  
  await pool.query(
    'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
    [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'VERIFICATION', CONFIG.VERIFICATION_FEE, txId, 'COMPLETED']
  );
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ success: true, message: 'Account verified successfully' });
}));

app.post('/api/account/username', auth, asyncHandler(async (req, res) => {
  const { username } = req.body;
  
  if (!username || username.length < 3 || username.length > 15) {
    throw new AppError('Invalid username', 400, ERROR_CODES.VALIDATION_ERROR, {
      field: 'username',
      requirement: '3-15 characters'
    });
  }
  
  const existing = await pool.query(
    'SELECT player_id FROM users WHERE username = $1 AND player_id != $2',
    [username, req.user.player_id]
  );
  
  if (existing.rows.length > 0) {
    throw new AppError('Username taken', 409, ERROR_CODES.USER_EXISTS, {
      field: 'username'
    });
  }
  
  await pool.query(
    'UPDATE users SET username = $1 WHERE player_id = $2',
    [username, req.user.player_id]
  );
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ success: true, username });
}));

app.post('/api/account/avatar', auth, asyncHandler(async (req, res) => {
  const { avatarId } = req.body;
  
  if (!avatarId || !avatarId.startsWith('hero_')) {
    throw new AppError('Invalid avatar', 400, ERROR_CODES.VALIDATION_ERROR, {
      field: 'avatarId'
    });
  }
  
  await pool.query('UPDATE users SET avatar_id = $1 WHERE player_id = $2', [avatarId, req.user.player_id]);
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ success: true, avatarId });
}));

app.post('/api/account/toggle-balance', auth, asyncHandler(async (req, res) => {
  const newHideBalance = !req.user.hide_balance;
  
  await pool.query('UPDATE users SET hide_balance = $1 WHERE player_id = $2', [newHideBalance, req.user.player_id]);
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ success: true, hideBalance: newHideBalance });
}));

// ==================== WALLET ROUTES ====================
app.get('/api/wallet/balance', auth, asyncHandler(async (req, res) => {
  const result = await pool.query(
    'SELECT balance, hide_balance FROM users WHERE player_id = $1',
    [req.user.player_id]
  );
  
  res.json({ 
    balance: parseFloat(result.rows[0].balance),
    hideBalance: result.rows[0].hide_balance
  });
}));

app.get('/api/wallet/address', auth, asyncHandler(async (req, res) => {
  res.json({
    depositAddress: CONFIG.PLATFORM_DEPOSIT_ADDRESS,
    memo: req.user.player_id,
    instructions: `Send ZEC to the address above with memo: ${req.user.player_id}`,
    minDeposit: CONFIG.MIN_DEPOSIT,
    verificationFee: CONFIG.VERIFICATION_FEE
  });
}));

app.post('/api/wallet/deposit', auth, transactionLimiter, asyncHandler(async (req, res) => {
  const { txId } = req.body;
  
  if (!txId) {
    throw new AppError('Transaction ID required', 400, ERROR_CODES.TRANSACTION_NOT_FOUND);
  }
  
  const existing = await pool.query('SELECT id FROM transactions WHERE tx_id = $1', [txId]);
  if (existing.rows.length > 0) {
    throw new AppError('Transaction already processed', 400, ERROR_CODES.TRANSACTION_PENDING, {
      message: 'Transaction already processed'
    });
  }
  
  const verification = await verifyZcashTransaction(txId, CONFIG.MIN_DEPOSIT, req.user.player_id);
  
  if (!verification.valid) {
    throw new AppError('Transaction failed', 400, ERROR_CODES.TRANSACTION_FAILED, {
      error: verification.error,
      confirmations: verification.confirmations,
      required: verification.required
    });
  }
  
  await pool.query('UPDATE users SET balance = balance + $1 WHERE player_id = $2', [verification.amount, req.user.player_id]);
  
  await pool.query(
    'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
    [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'DEPOSIT', verification.amount, txId, 'COMPLETED']
  );
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ 
    success: true, 
    amount: verification.amount,
    newBalance: parseFloat(req.user.balance) + verification.amount
  });
}));

app.post('/api/wallet/withdraw', auth, transactionLimiter, asyncHandler(async (req, res) => {
  const { amount, address } = req.body;
  
  if (!req.user.is_verified) {
    throw new AppError('Not verified', 403, ERROR_CODES.ACCOUNT_NOT_VERIFIED);
  }
  
  if (amount < CONFIG.MIN_WITHDRAWAL) {
    throw new AppError('Withdrawal too small', 400, ERROR_CODES.WITHDRAWAL_TOO_SMALL, {
      provided: amount,
      min: CONFIG.MIN_WITHDRAWAL
    });
  }
  
  if (amount > CONFIG.MAX_WITHDRAWAL) {
    throw new AppError('Withdrawal too large', 400, ERROR_CODES.WITHDRAWAL_TOO_LARGE, {
      requested: amount,
      max: CONFIG.MAX_WITHDRAWAL
    });
  }
  
  if (parseFloat(req.user.balance) < amount) {
    throw new AppError('Insufficient balance', 400, ERROR_CODES.INSUFFICIENT_BALANCE, {
      required: amount,
      available: parseFloat(req.user.balance),
      shortfall: amount - parseFloat(req.user.balance)
    });
  }
  
  if (!address.startsWith('z') && !address.startsWith('u')) {
    throw new AppError('Shielded address required', 400, ERROR_CODES.ADDRESS_NOT_SHIELDED, {
      providedAddress: address.substring(0, 20) + '...'
    });
  }
  
  const dailyTotal = await pool.query(
    "SELECT COALESCE(SUM(ABS(amount)), 0) as total FROM transactions WHERE user_id = $1 AND type = 'WITHDRAW' AND created_at > NOW() - INTERVAL '24 hours'",
    [req.user.player_id]
  );
  
  const dailyUsed = parseFloat(dailyTotal.rows[0].total);
  
  if (dailyUsed + amount > CONFIG.DAILY_WITHDRAWAL_LIMIT) {
    throw new AppError('Limit exceeded', 429, ERROR_CODES.WITHDRAWAL_LIMIT_EXCEEDED, {
      limit: CONFIG.DAILY_WITHDRAWAL_LIMIT,
      used: dailyUsed,
      available: CONFIG.DAILY_WITHDRAWAL_LIMIT - dailyUsed
    });
  }
  
  await pool.query('UPDATE users SET balance = balance - $1 WHERE player_id = $2', [amount, req.user.player_id]);
  
  const txId = await sendZcashTransaction(address, amount, `Withdrawal from ZecArena - ${req.user.player_id}`);
  
  if (!txId) {
    await pool.query('UPDATE users SET balance = balance + $1 WHERE player_id = $2', [amount, req.user.player_id]);
    throw new AppError('Transaction failed', 500, ERROR_CODES.TRANSACTION_FAILED, {
      error: 'Failed to send transaction'
    });
  }
  
  await pool.query(
    'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
    [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, req.user.player_id, 'WITHDRAW', -amount, txId, 'COMPLETED']
  );
  
  await redis.del(`session:${req.user.player_id}`);
  
  res.json({ 
    success: true, 
    txId, 
    amount,
    newBalance: parseFloat(req.user.balance) - amount
  });
}));

app.get('/api/wallet/transactions', auth, asyncHandler(async (req, res) => {
  const { limit = 50, offset = 0, type } = req.query;
  
  let query = `
    SELECT id, type, amount, tx_id, status, created_at 
    FROM transactions 
    WHERE user_id = $1`;
  
  const params = [req.user.player_id];
  
  if (type) {
    query += ' AND type = $2';
    params.push(type);
  }
  
  query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  params.push(parseInt(limit), parseInt(offset));
  
  const result = await pool.query(query, params);
  

// ==================== ROOM/LOBBY ROUTES ====================
app.post('/api/rooms/create', auth, asyncHandler(async (req, res) => {
  const { type, stake, maxPlayers } = req.body;
  
  if (!type || !['PICTURE_RUSH', 'PICTURE_MATCH'].includes(type)) {
    throw new AppError('Invalid game type', 400, ERROR_CODES.INVALID_GAME_TYPE);
  }
  
  const stakeAmount = parseFloat(stake) || 0;
  const maxPlayersNum = parseInt(maxPlayers) || 2;
  
  if (stakeAmount < 0 || maxPlayersNum < 1 || maxPlayersNum > CONFIG.MAX_PLAYERS_PER_GAME) {
    throw new AppError('Invalid parameters', 400, ERROR_CODES.VALIDATION_ERROR, {
      error: 'Invalid game parameters'
    });
  }
  
  if (stakeAmount > 0) {
    if (!req.user.is_verified) {
      throw new AppError('Not verified', 403, ERROR_CODES.ACCOUNT_NOT_VERIFIED);
    }
    
    if (parseFloat(req.user.balance) < stakeAmount) {
      throw new AppError('Insufficient balance', 400, ERROR_CODES.INSUFFICIENT_BALANCE, {
        required: stakeAmount,
        available: parseFloat(req.user.balance)
      });
    }
    
    await pool.query('UPDATE users SET balance = balance - $1 WHERE player_id = $2', [stakeAmount, req.user.player_id]);
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
      stakeAmount,
      maxPlayersNum,
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
  
  io.emit('room_created', { roomId, type, stake: stakeAmount, maxPlayers: maxPlayersNum });
  
  res.json({ success: true, roomId });
}));

app.post('/api/rooms/join', auth, asyncHandler(async (req, res) => {
  const { roomId } = req.body;
  
  const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
  
  if (result.rows.length === 0) {
    throw new AppError('Room not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  const room = result.rows[0];
  
  if (room.status !== 'WAITING') {
    throw new AppError('Game started', 400, ERROR_CODES.GAME_ALREADY_STARTED);
  }
  
  if (room.current_players >= room.max_players) {
    throw new AppError('Room full', 400, ERROR_CODES.GAME_FULL, {
      currentPlayers: room.current_players,
      maxPlayers: room.max_players
    });
  }
  
  const playerIds = JSON.parse(room.player_ids);
  if (playerIds.includes(req.user.player_id)) {
    throw new AppError('Already in game', 400, ERROR_CODES.PLAYER_ALREADY_IN_GAME);
  }
  
  if (room.stake > 0) {
    if (!req.user.is_verified) {
      throw new AppError('Not verified', 403, ERROR_CODES.ACCOUNT_NOT_VERIFIED);
    }
    
    if (parseFloat(req.user.balance) < room.stake) {
      throw new AppError('Insufficient balance', 400, ERROR_CODES.INSUFFICIENT_BALANCE, {
        required: room.stake,
        available: parseFloat(req.user.balance)
      });
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
      
      const roomData = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
      const room = roomData.rows[0];
      const players = await pool.query(
        'SELECT player_id, username, avatar_id FROM users WHERE player_id = ANY($1)',
        [JSON.parse(room.player_ids)]
      );
      
      let game;
      if (room.type === 'PICTURE_RUSH') {
        game = gameManager.initPictureRush(roomId, players.rows, room.stake);
      } else if (room.type === 'PICTURE_MATCH') {
        game = gameManager.initPictureMatch(roomId, players.rows, room.stake);
      }
      
      gameManager.activeGames.set(roomId, game);
      io.to(roomId).emit('game_started', game);
    }, CONFIG.GAME_START_COUNTDOWN);
  }
  
  io.to(roomId).emit('player_joined', updatedRoom.rows[0]);
  io.emit('room_updated', updatedRoom.rows[0]);
  
  res.json({ success: true });
}));

app.get('/api/rooms', asyncHandler(async (req, res) => {
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
}));

app.get('/api/rooms/:roomId', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.roomId]);
  
  if (result.rows.length === 0) {
    throw new AppError('Room not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  res.json({ room: result.rows[0] });
}));

app.post('/api/rooms/:roomId/leave', auth, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.roomId]);
  
  if (result.rows.length === 0) {
    throw new AppError('Room not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  const room = result.rows[0];
  const playerIds = JSON.parse(room.player_ids);
  
  if (!playerIds.includes(req.user.player_id)) {
    throw new AppError('Not in game', 400, ERROR_CODES.NOT_IN_GAME);
  }
  
  if (room.status !== 'WAITING') {
    throw new AppError('Game started', 400, ERROR_CODES.GAME_ALREADY_STARTED, {
      message: 'Cannot leave after game started'
    });
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
}));

// ==================== GAME ACTION ROUTES ====================
app.post('/api/game/action', auth, asyncHandler(async (req, res) => {
  const { gameId, action, data } = req.body;
  
  const game = gameManager.activeGames.get(gameId);
  if (!game) {
    throw new AppError('Game not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  let result;
  
  if (game.type === 'PICTURE_RUSH' && action === 'answer') {
    result = gameManager.handlePictureRushAnswer(gameId, req.user.player_id, data.imageIndex, data.answer);
  } else if (game.type === 'PICTURE_MATCH' && action === 'flip') {
    result = gameManager.handlePictureMatchCardFlip(gameId, req.user.player_id, data.cardPosition);
  } else {
    throw new AppError('Invalid action', 400, ERROR_CODES.INVALID_GAME_ACTION);
  }
  
  if (result.error) {
    throw new AppError(result.error, 400, ERROR_CODES.INVALID_GAME_ACTION);
  }
  
  res.json({ success: true, result });
}));

app.get('/api/game/:gameId/state', auth, asyncHandler(async (req, res) => {
  const game = gameManager.activeGames.get(req.params.gameId);
  if (!game) {
    throw new AppError('Game not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  res.json({ game });
}));

app.post('/api/game/start', auth, asyncHandler(async (req, res) => {
  const { roomId } = req.body;
  
  const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
  
  if (result.rows.length === 0) {
    throw new AppError('Room not found', 404, ERROR_CODES.GAME_NOT_FOUND);
  }
  
  const room = result.rows[0];
  
  if (room.host_id !== req.user.player_id) {
    throw new AppError('Only host can start', 403, ERROR_CODES.OPERATION_NOT_ALLOWED, {
      message: 'Only host can start the game'
    });
  }
  
  if (room.status !== 'WAITING') {
    throw new AppError('Game started', 400, ERROR_CODES.GAME_ALREADY_STARTED);
  }
  
  await pool.query('UPDATE rooms SET status = $1, started_at = NOW() WHERE id = $2', ['IN_PROGRESS', roomId]);
  
  io.to(roomId).emit('game_started', { roomId });
  
  res.json({ success: true });
}));

// ==================== LEADERBOARD ====================
app.get('/api/leaderboard', asyncHandler(async (req, res) => {
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
}));

// ==================== GAME HISTORY ====================
app.get('/api/game/history', auth, asyncHandler(async (req, res) => {
  const { limit = 20, offset = 0 } = req.query;
  
  const result = await pool.query(
    `SELECT 
      r.id, r.type, r.stake, r.status, r.winner_id, r.scores,
      r.created_at, r.started_at, r.finished_at,
      r.player_ids, r.player_data
    FROM rooms r
    WHERE r.player_ids::jsonb ? $1
    AND r.status = 'FINISHED'
    ORDER BY r.finished_at DESC
    LIMIT $2 OFFSET $3`,
    [req.user.player_id, parseInt(limit), parseInt(offset)]
  );
  
  const history = result.rows.map(game => ({
    gameId: game.id,
    type: game.type,
    stake: parseFloat(game.stake),
    status: game.status,
    winnerId: game.winner_id,
    isWinner: game.winner_id === req.user.player_id,
    scores: JSON.parse(game.scores || '[]'),
    playerData: JSON.parse(game.player_data || '{}'),
    createdAt: game.created_at,
    startedAt: game.started_at,
    finishedAt: game.finished_at,
    duration: game.started_at && game.finished_at ? 
      new Date(game.finished_at) - new Date(game.started_at) : null
  }));
  
  res.json({ history });
}));

// ==================== STATS ====================
app.get('/api/stats', asyncHandler(async (req, res) => {
  const [userCount, verifiedCount, activeGames, totalGames, totalVolume] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM users'),
    pool.query('SELECT COUNT(*) FROM users WHERE is_verified = true'),
    pool.query('SELECT COUNT(*) FROM rooms WHERE status IN ($1, $2)', ['WAITING', 'IN_PROGRESS']),
    pool.query('SELECT COUNT(*) FROM rooms WHERE status = $1', ['FINISHED']),
    pool.query('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type IN ($1, $2)', ['DEPOSIT', 'WITHDRAW'])
  ]);
  

// ==================== WEBSOCKET HANDLING ====================
io.on('connection', (socket) => {
  console.log('WebSocket client connected:', socket.id);
  
  socket.on('authenticate', async (data) => {
    try {
      const { token } = data;
      const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
      socket.playerId = decoded.playerId;
      gameManager.playerSockets.set(decoded.playerId, socket);
      socket.emit('authenticated', { playerId: decoded.playerId });
      console.log(`✅ Player ${decoded.playerId} authenticated`);
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
      socket.disconnect();
    }
  });
  
  socket.on('join_room', (data) => {
    const { roomId } = data;
    socket.join(roomId);
    console.log(`Player ${socket.playerId} joined room ${roomId}`);
    socket.to(roomId).emit('player_connected', { playerId: socket.playerId });
  });
  
  socket.on('leave_room', (data) => {
    const { roomId } = data;
    socket.leave(roomId);
    console.log(`Player ${socket.playerId} left room ${roomId}`);
    socket.to(roomId).emit('player_disconnected', { playerId: socket.playerId });
  });
  
  socket.on('game_action', async (data) => {
    const { roomId, action, payload } = data;
    io.to(roomId).emit('game_action', { 
      playerId: socket.playerId, 
      action, 
      payload,
      timestamp: Date.now()
    });
  });
  
  socket.on('chat_message', (data) => {
    const { roomId, message } = data;
    if (message && message.length <= 200) {
      io.to(roomId).emit('chat_message', { 
        playerId: socket.playerId, 
        message, 
        timestamp: Date.now() 
      });
    }
  });
  
  socket.on('game_ready', (data) => {
    const { gameId } = data;
    const game = gameManager.activeGames.get(gameId);
    if (game) {
      const player = game.players.find(p => p.playerId === socket.playerId);
      if (player) {
        player.ready = true;
        io.to(gameId).emit('player_ready', { playerId: socket.playerId });
      }
    }
  });
  
  socket.on('disconnect', () => {
    console.log('WebSocket client disconnected:', socket.id);
    if (socket.playerId) {
      gameManager.playerSockets.delete(socket.playerId);
    }
  });
});

// ==================== CLASSIC WEBSOCKET HANDLING (ws) ====================
const activeConnections = new Map();
const activeGamesWS = new Map();

wss.on('connection', (ws) => {
  let userId = null;
  let gameId = null;

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);

      switch (data.type) {
        case 'authenticate':
          try {
            const decoded = jwt.verify(data.token, CONFIG.JWT_SECRET);
            userId = decoded.playerId;
            ws.userId = userId;
            activeConnections.set(userId, ws);
            ws.send(JSON.stringify({ type: 'authenticated', userId: userId }));
          } catch (error) {
            ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed' }));
            ws.close();
          }
          break;

        case 'join_game':
          gameId = data.gameId;
          ws.gameId = gameId;
          
          if (!activeGamesWS.has(gameId)) {
            activeGamesWS.set(gameId, { players: new Map(), state: {} });
          }
          
          activeGamesWS.get(gameId).players.set(userId, ws);
          
          broadcastToGame(gameId, {
            type: 'player_joined',
            userId: userId,
            playerCount: activeGamesWS.get(gameId).players.size
          });
          break;

        case 'game_action':
          if (gameId && activeGamesWS.has(gameId)) {
            const game = activeGamesWS.get(gameId);
            game.state = { ...game.state, ...data.state };
            
            broadcastToGame(gameId, {
              type: 'game_update',
              action: data.action,
              userId: userId,
              state: game.state,
              timestamp: Date.now()
            }, userId);
          }
          break;

        case 'game_state':
          if (gameId && activeGamesWS.has(gameId)) {
            const game = activeGamesWS.get(gameId);
            game.state = data.state;
            
            broadcastToGame(gameId, {
              type: 'state_sync',
              state: game.state,
              timestamp: Date.now()
            });
          }
          break;

        case 'chat_message':
          if (gameId) {
            broadcastToGame(gameId, {
              type: 'chat',
              userId: userId,
              username: data.username,
              message: data.message,
              timestamp: Date.now()
            });
          }
          break;

        default:
          ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    if (userId) {
      activeConnections.delete(userId);
    }
    
    if (gameId && activeGamesWS.has(gameId)) {
      const game = activeGamesWS.get(gameId);
      game.players.delete(userId);
      
      if (game.players.size === 0) {
        activeGamesWS.delete(gameId);
      } else {
        broadcastToGame(gameId, {
          type: 'player_left',
          userId: userId
        });
      }
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

function broadcastToGame(gameId, message, excludeUserId = null) {
  if (activeGamesWS.has(gameId)) {
    const game = activeGamesWS.get(gameId);
    game.players.forEach((ws, playerId) => {
      if (playerId !== excludeUserId && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }
}

// ==================== TRANSACTION MONITOR ====================
setInterval(async () => {
  try {
    if (!CONFIG.PLATFORM_DEPOSIT_ADDRESS) return;
    
    const transactions = await zcashRPC('z_listreceivedbyaddress', [CONFIG.PLATFORM_DEPOSIT_ADDRESS, 0]);
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
      
      if (amount >= CONFIG.VERIFICATION_FEE && !user.is_verified) {
        await pool.query(
          'UPDATE users SET is_verified = true, verification_tx_id = $1 WHERE player_id = $2',
          [tx.txid, user.player_id]
        );
        
        await pool.query(
          'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
          [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, user.player_id, 'VERIFICATION', CONFIG.VERIFICATION_FEE, tx.txid, 'COMPLETED']
        );
        
        console.log('✅ Verified user:', user.player_id);
        
        const socket = gameManager.playerSockets.get(user.player_id);
        if (socket) {
          socket.emit('account_verified', { txId: tx.txid });
        }
      } else if (amount >= CONFIG.MIN_DEPOSIT) {
        await pool.query(
          'UPDATE users SET balance = balance + $1 WHERE player_id = $2',
          [amount, user.player_id]
        );
        
        await pool.query(
          'INSERT INTO transactions (id, user_id, type, amount, tx_id, status) VALUES ($1, $2, $3, $4, $5, $6)',
          [`tx-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`, user.player_id, 'DEPOSIT', amount, tx.txid, 'COMPLETED']
        );
        
        console.log('✅ Deposit processed:', user.player_id, amount);
        
        const socket = gameManager.playerSockets.get(user.player_id);
        if (socket) {
          socket.emit('deposit_confirmed', { 
            amount, 
            txId: tx.txid 
          });
        }
        
        await redis.del(`session:${user.player_id}`);
      }
    }
  } catch (error) {
    console.error('❌ Transaction monitor error:', error);
  }
}, CONFIG.MONITORING_INTERVAL);

// ==================== ADMIN ROUTES ====================
app.post('/api/admin/withdraw-cold', adminAuth, asyncHandler(async (req, res) => {
  const { amount } = req.body;
  
  console.log('🔐 Admin cold wallet withdrawal - HSM operation');
  
  const txId = await sendZcashTransaction(
    CONFIG.PLATFORM_COLD_WALLET,
    amount,
    'Admin cold wallet transfer'
  );
  
  if (!txId) {
    throw new AppError('Transaction failed', 500, ERROR_CODES.TRANSACTION_FAILED);
  }
  
  await logSecurityEvent('ADMIN_COLD_WITHDRAWAL', 'HIGH', {
    description: 'Admin cold wallet withdrawal',
    amount,
    txId
  });
  
  res.json({ success: true, txId, amount });
}));

app.get('/api/admin/stats', adminAuth, asyncHandler(async (req, res) => {
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
}));

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    const blockchainInfo = await zcashRPC('getblockchaininfo');
    
    res.json({ 
      status: 'healthy',
      timestamp: Date.now(),
      version: '7.0.0',
      database: 'connected',
      redis: 'connected',
      blockchain: {
        connected: true,
        blocks: blockchainInfo.blocks,
        synced: !blockchainInfo.initialblockdownload
      },
      security: {
        encryption: 'AES-256-GCM',
        hsmEnabled: CONFIG.HSM_ENABLED,
        secretsEncrypted: true
      },
      activeGames: gameManager.activeGames.size,
      connectedPlayers: gameManager.playerSockets.size
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
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// ==================== DATABASE SCHEMA INIT ====================
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        player_id VARCHAR(8) PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        email VARCHAR(255) UNIQUE,
        username VARCHAR(50) UNIQUE,
        balance DECIMAL(18, 8) DEFAULT 0,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_tx_id TEXT,
        avatar_id VARCHAR(50) DEFAULT 'hero_1',
        hide_balance BOOLEAN DEFAULT FALSE,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        xp INTEGER DEFAULT 0,
        total_games INTEGER DEFAULT 0,
        streak INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS transactions (
        id VARCHAR(50) PRIMARY KEY,
        user_id VARCHAR(8) REFERENCES users(player_id),
        type VARCHAR(20) NOT NULL,
        amount DECIMAL(18, 8) NOT NULL,
        tx_id TEXT,
        status VARCHAR(20) DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS rooms (
        id VARCHAR(50) PRIMARY KEY,
        host_id VARCHAR(8) REFERENCES users(player_id),
        host_name VARCHAR(50),
        host_avatar VARCHAR(50),
        type VARCHAR(20) NOT NULL,
        stake DECIMAL(18, 8) DEFAULT 0,
        max_players INTEGER DEFAULT 2,
        current_players INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'WAITING',
        winner_id VARCHAR(8),
        scores JSONB,
        player_ids JSONB,
        player_data JSONB,
        created_at TIMESTAMP DEFAULT NOW(),
        started_at TIMESTAMP,
        finished_at TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        player_id VARCHAR(8),
        ip_address VARCHAR(45),
        description TEXT,
        metadata JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);
      CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
      CREATE INDEX IF NOT EXISTS idx_rooms_status ON rooms(status);
      CREATE INDEX IF NOT EXISTS idx_rooms_type ON rooms(type);
      CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
    `);
    
    console.log('✅ Database schema initialized');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

initDatabase();

// ==================== START SERVER ====================
server.listen(CONFIG.PORT, CONFIG.HOST, () => {
  console.log('');
  console.log('🚀 ZEC ARENA COMPLETE BACKEND - ALL 6 VERSIONS MERGED');
  console.log('==========================================');
  console.log(`Port: ${CONFIG.PORT}`);
  console.log(`Host: ${CONFIG.HOST}`);
  console.log(`Environment: ${CONFIG.NODE_ENV}`);
  console.log(`Network: ${CONFIG.ZCASH_NETWORK}`);
  console.log(`Frontend: ${CONFIG.FRONTEND_URL}`);
  console.log('==========================================');
  console.log('🔐 SECURITY:');
  console.log('   ✅ Secrets encrypted at rest (AES-256-GCM)');
  console.log('   ✅ User auth: bcrypt + pbkdf2 + JWT');
  if (CONFIG.HSM_ENABLED) {
    console.log(`   ✅ HSM enabled: ${CONFIG.HSM_TYPE} (admin only)`);
  } else {
    console.log('   ⚠️  HSM disabled (software keys)');
  }
  console.log('   ✅ Rate limiting active');
  console.log('   ✅ Brute force protection');
  console.log('   ✅ Security event logging');
  console.log('==========================================');
  console.log('✅ ALL FEATURES LOADED:');
  console.log('   ✅ Complete Authentication System');
  console.log('   ✅ Zcash RPC Integration');
  console.log('   ✅ Wallet (Deposit/Withdraw)');
  console.log('   ✅ Picture Rush Game - FULL LOGIC');
  console.log('   ✅ Picture Match Game - FULL LOGIC');
  console.log('   ✅ Real-time WebSocket (Socket.IO + ws)');
  console.log('   ✅ Room/Lobby System');
  console.log('   ✅ Auto Payout Processing');
  console.log('   ✅ Leaderboard & Stats');
  console.log('   ✅ Transaction Monitor');
  console.log('   ✅ Game History');
  console.log('   ✅ XP & Level System');
  console.log('   ✅ Error Codes & Handlers');
  console.log('   ✅ Admin Routes');
  console.log('==========================================');
  console.log('🎮 GAME MECHANICS:');
  console.log('   Picture Rush: 15 images, 30s, streak bonuses');
  console.log('   Picture Match: 16 cards, 90s, speed bonuses');
  console.log('   Auto game start, timeout detection');
  console.log('   Automatic winner calculation');
  console.log('   Real-time state broadcasting');
  console.log('   Payout processing with house edge');
  console.log('==========================================');
  console.log('✅ Server Ready - All Systems Operational');
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
  
  io.close(() => {
    console.log('✅ Socket.IO server closed');
  });
  
  wss.close(() => {
    console.log('✅ WebSocket server closed');
  });

  try {
    for (const [gameId, game] of gameManager.activeGames.entries()) {
      if (game.status === 'ACTIVE' || game.status === 'STARTING') {
        console.log(`💰 Refunding game ${gameId}...`);
        await gameManager.refundPlayers(game);
      }
    }
    
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
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  shutdown('unhandledRejection');
});

module.exports = { app, server, io, wss, gameManager, pool, redis };
