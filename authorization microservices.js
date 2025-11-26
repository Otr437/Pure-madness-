// ==================== AUTHENTICATION MICROSERVICE ====================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const Redis = require('ioredis');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.AUTH_PORT || 3002;

// Security
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 signups
  message: { error: 'Too many signup attempts, please try again later' }
});

// Database
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'zec_arena',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  max: 20
});

// Redis
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRES = '24h';

// ==================== ERROR HANDLING ====================
const ERROR_CODES = {
  INVALID_CREDENTIALS: 1000,
  ACCOUNT_LOCKED: 1001,
  TOKEN_EXPIRED: 1002,
  TOKEN_INVALID: 1003,
  PASSWORD_WEAK: 1004,
  USER_NOT_FOUND: 1005,
  USER_EXISTS: 1006,
  SESSION_EXPIRED: 1007,
  RATE_LIMIT_EXCEEDED: 5004
};

function buildErrorResponse(errorCode, details = {}) {
  const errors = {
    [ERROR_CODES.INVALID_CREDENTIALS]: {
      message: 'Invalid credentials',
      userMessage: 'The username/Player ID or password you entered is incorrect.',
      action: 'Check your credentials and try again'
    },
    [ERROR_CODES.ACCOUNT_LOCKED]: {
      message: 'Account temporarily locked',
      userMessage: `Your account has been locked due to ${details.attempts || 5} failed login attempts.`,
      action: 'Wait 1 hour or contact support to unlock your account'
    },
    [ERROR_CODES.TOKEN_EXPIRED]: {
      message: 'Session expired',
      userMessage: 'Your session has expired. Please log in again.',
      action: 'Log in to continue'
    },
    [ERROR_CODES.TOKEN_INVALID]: {
      message: 'Invalid token',
      userMessage: 'Your session is invalid.',
      action: 'Please log in again'
    },
    [ERROR_CODES.PASSWORD_WEAK]: {
      message: 'Password too weak',
      userMessage: 'Password must be at least 8 characters with uppercase, lowercase, and numbers.',
      action: 'Create a stronger password (e.g., MyP@ssw0rd123)'
    },
    [ERROR_CODES.USER_NOT_FOUND]: {
      message: 'User not found',
      userMessage: 'No account found with that Player ID or username.',
      action: 'Check your Player ID or create a new account'
    },
    [ERROR_CODES.USER_EXISTS]: {
      message: 'User already exists',
      userMessage: 'An account with this username or email already exists.',
      action: 'Try logging in or use a different username/email'
    },
    [ERROR_CODES.SESSION_EXPIRED]: {
      message: 'Session expired',
      userMessage: 'Your session has expired.',
      action: 'Please log in again'
    },
    [ERROR_CODES.RATE_LIMIT_EXCEEDED]: {
      message: 'Too many attempts',
      userMessage: `You're making too many requests. Please wait ${details.retryAfter || '15 minutes'}.`,
      action: 'Slow down and try again later'
    }
  };

  const errorInfo = errors[errorCode] || {
    message: 'An error occurred',
    userMessage: 'Something went wrong. Please try again.',
    action: 'If the problem persists, contact support'
  };

  return {
    error: true,
    errorCode,
    message: errorInfo.message,
    userMessage: errorInfo.userMessage,
    action: errorInfo.action,
    details,
    timestamp: new Date().toISOString(),
    support: 'support@zecarena.com'
  };
}

// Security event logging
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
      [type, severity, details.playerId || null, details.ipAddress || null, details.description || null, details.metadata ? JSON.stringify(details.metadata) : null]
    );
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
}

// Brute force protection
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
    await redis.expire(key, 3600); // 1 hour
  }
  
  return current;
}

// ==================== SIGNUP ====================
app.post('/signup', signupLimiter, async (req, res) => {
  try {
    const { password, email, username } = req.body;
    
    if (!password || password.length < 8) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PASSWORD_WEAK, {
        requirement: 'At least 8 characters'
      }));
    }

    // Password strength check
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
      'INSERT INTO users (player_id, password_hash, salt, email, username) VALUES ($1, $2, $3, $4, $5)',
      [playerId, hash, salt, email || null, username || null]
    );

    const token = jwt.sign({ playerId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

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
      nextStep: 'Log in with your new Player ID'
    });
  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === '23505') { // Unique violation
      return res.status(400).json(buildErrorResponse(ERROR_CODES.USER_EXISTS, {
        field: error.constraint?.includes('username') ? 'username' : 'email'
      }));
    }
    
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Registration failed'
    }));
  }
});

// ==================== LOGIN ====================
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { playerId, password } = req.body;

    // Check brute force
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

    // Clear brute force on successful login
    await redis.del(`bruteforce:${user.player_id}`);

    await pool.query(
      'UPDATE users SET last_login = NOW(), login_count = login_count + 1 WHERE player_id = $1',
      [user.player_id]
    );

    const token = jwt.sign({ playerId: user.player_id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // Cache user session
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
      sessionExpires: '24 hours'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Login failed'
    }));
  }
});

// ==================== VERIFY TOKEN ====================
app.post('/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID, {
        reason: 'No token provided'
      }));
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
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
    
    // Check cache first
    const cached = await redis.get(`session:${decoded.playerId}`);
    if (cached) {
      return res.json({ valid: true, user: JSON.parse(cached) });
    }

    // Get from DB
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
    console.error('Token verification error:', error);
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Verification failed'
    }));
  }
});

// ==================== LOGOUT ====================
app.post('/logout', async (req, res) => {
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
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Logout failed'
    }));
  }
});

// ==================== REFRESH TOKEN ====================
app.post('/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID, {
        reason: 'No token provided'
      }));
    }
    
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_EXPIRED, {
          message: 'Please log in again'
        }));
      }
      return res.status(401).json(buildErrorResponse(ERROR_CODES.TOKEN_INVALID));
    }
    
    const newToken = jwt.sign({ playerId: decoded.playerId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    
    res.json({ 
      success: true,
      token: newToken,
      expiresIn: '24 hours'
    });
  } catch (error) {
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Token refresh failed'
    }));
  }
});

// ==================== CHANGE PASSWORD ====================
app.post('/change-password', async (req, res) => {
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
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Password change failed'
    }));
  }
});

// ==================== HEALTH ====================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({ status: 'healthy', service: 'auth' });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🔐 Auth Service running on port ${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json(buildErrorResponse(5006, {
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  }));
});

module.exports = app;