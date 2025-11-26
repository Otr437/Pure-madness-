// ==================== ADMIN CONTROLLER ====================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const Redis = require('ioredis');
const axios = require('axios');

const app = express();
const PORT = process.env.ADMIN_PORT || 3001;

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'zec_arena',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  max: 20
});

const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

// ==================== ERROR HANDLING ====================
const ERROR_CODES = {
  ADMIN_ACCESS_REQUIRED: 6000,
  INVALID_ADMIN_KEY: 6001,
  OPERATION_NOT_ALLOWED: 6002,
  USER_NOT_FOUND: 1005,
  GAME_NOT_FOUND: 4000,
  WITHDRAWAL_NOT_FOUND: 2009,
  SERVICE_UNAVAILABLE: 5005,
  DATABASE_ERROR: 5000
};

function buildErrorResponse(errorCode, details = {}) {
  const errors = {
    [ERROR_CODES.ADMIN_ACCESS_REQUIRED]: {
      message: 'Admin access required',
      userMessage: 'You don\'t have permission to access this resource.',
      action: 'Contact an administrator'
    },
    [ERROR_CODES.INVALID_ADMIN_KEY]: {
      message: 'Invalid admin key',
      userMessage: 'The admin API key provided is invalid.',
      action: 'Check your API key configuration'
    },
    [ERROR_CODES.OPERATION_NOT_ALLOWED]: {
      message: 'Operation not allowed',
      userMessage: `This operation cannot be performed: ${details.reason || 'Unknown reason'}`,
      action: details.suggestion || 'Review the operation requirements'
    },
    [ERROR_CODES.USER_NOT_FOUND]: {
      message: 'User not found',
      userMessage: `No user found with ID: ${details.playerId}`,
      action: 'Check the Player ID and try again'
    },
    [ERROR_CODES.GAME_NOT_FOUND]: {
      message: 'Game not found',
      userMessage: `No game found with ID: ${details.gameId}`,
      action: 'Check the Game ID and try again'
    },
    [ERROR_CODES.WITHDRAWAL_NOT_FOUND]: {
      message: 'Withdrawal not found',
      userMessage: `No withdrawal found with ID: ${details.withdrawalId}`,
      action: 'Check the Withdrawal ID and try again'
    },
    [ERROR_CODES.SERVICE_UNAVAILABLE]: {
      message: 'Service unavailable',
      userMessage: `The ${details.service} service is currently unavailable.`,
      action: 'Check service health or try again later'
    },
    [ERROR_CODES.DATABASE_ERROR]: {
      message: 'Database error',
      userMessage: 'A database error occurred.',
      action: 'Check database connection and try again'
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
    support: 'admin@zecarena.com'
  };
}

// ==================== ADMIN AUTH ====================
function requireAdminKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!process.env.ADMIN_API_KEY || apiKey === process.env.ADMIN_API_KEY) {
    return next();
  }
  res.status(403).json({ error: 'Admin access required' });
}

app.use(requireAdminKey);

// ==================== SERVICE URLS ====================
const SERVICES = {
  AUTH: process.env.AUTH_SERVICE_URL || 'http://localhost:3002',
  WALLET: process.env.WALLET_SERVICE_URL || 'http://localhost:3003',
  GAME: process.env.GAME_SERVICE_URL || 'http://localhost:3004',
  MONITOR: process.env.MONITOR_SERVICE_URL || 'http://localhost:3005'
};

// ==================== DASHBOARD ====================
app.get('/dashboard', async (req, res) => {
  try {
    const [users, games, transactions, platformStats] = await Promise.all([
      pool.query('SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_verified = TRUE) as verified FROM users'),
      pool.query('SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = \'IN_PROGRESS\') as active FROM games'),
      pool.query(`
        SELECT 
          COUNT(*) FILTER (WHERE type = 'DEPOSIT' AND status = 'confirmed') as deposits,
          COUNT(*) FILTER (WHERE type = 'WITHDRAW' AND status IN ('confirmed', 'confirming')) as withdrawals,
          COALESCE(SUM(amount) FILTER (WHERE type = 'DEPOSIT' AND status = 'confirmed'), 0) as total_deposits,
          COALESCE(SUM(amount) FILTER (WHERE type = 'WITHDRAW' AND status IN ('confirmed', 'confirming')), 0) as total_withdrawals,
          COALESCE(SUM(amount) FILTER (WHERE type = 'FEE'), 0) as total_fees
        FROM transactions
      `),
      pool.query(`
        SELECT 
          COALESCE(SUM(balance), 0) as total_user_balance,
          COUNT(*) FILTER (WHERE last_login > NOW() - INTERVAL '24 hours') as active_24h
        FROM users
      `)
    ]);

    const [authHealth, walletHealth, gameHealth, monitorHealth] = await Promise.allSettled([
      axios.get(`${SERVICES.AUTH}/health`).then(r => r.data),
      axios.get(`${SERVICES.WALLET}/health`).then(r => r.data),
      axios.get(`${SERVICES.GAME}/health`).then(r => r.data),
      axios.get(`${SERVICES.MONITOR}/health`).then(r => r.data)
    ]);

    res.json({
      users: {
        total: parseInt(users.rows[0].total),
        verified: parseInt(users.rows[0].verified),
        active24h: parseInt(platformStats.rows[0].active_24h)
      },
      games: {
        total: parseInt(games.rows[0].total),
        active: parseInt(games.rows[0].active)
      },
      transactions: {
        deposits: parseInt(transactions.rows[0].deposits),
        withdrawals: parseInt(transactions.rows[0].withdrawals),
        totalDepositsAmount: parseFloat(transactions.rows[0].total_deposits),
        totalWithdrawalsAmount: parseFloat(transactions.rows[0].total_withdrawals),
        totalFees: parseFloat(transactions.rows[0].total_fees)
      },
      platform: {
        totalUserBalance: parseFloat(platformStats.rows[0].total_user_balance),
        revenue: parseFloat(transactions.rows[0].total_fees)
      },
      services: {
        auth: authHealth.status === 'fulfilled' ? authHealth.value : { status: 'unhealthy' },
        wallet: walletHealth.status === 'fulfilled' ? walletHealth.value : { status: 'unhealthy' },
        game: gameHealth.status === 'fulfilled' ? gameHealth.value : { status: 'unhealthy' },
        monitor: monitorHealth.status === 'fulfilled' ? monitorHealth.value : { status: 'unhealthy' }
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

// ==================== USERS MANAGEMENT ====================
app.get('/users', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const search = req.query.search;

    let query = 'SELECT player_id, username, email, balance, is_verified, wallet_address, last_login, created_at FROM users';
    const params = [];

    if (search) {
      query += ' WHERE player_id ILIKE $1 OR username ILIKE $1 OR email ILIKE $1';
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({
      users: result.rows.map(u => ({
        playerId: u.player_id,
        username: u.username,
        email: u.email,
        balance: parseFloat(u.balance),
        isVerified: u.is_verified,
        walletAddress: u.wallet_address,
        lastLogin: u.last_login,
        createdAt: u.created_at
      })),
      limit,
      offset
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/users/:playerId', async (req, res) => {
  try {
    const { playerId } = req.params;

    const [user, txCount, gameCount] = await Promise.all([
      pool.query('SELECT * FROM users WHERE player_id = $1', [playerId]),
      pool.query('SELECT COUNT(*) as count FROM transactions WHERE player_id = $1', [playerId]),
      pool.query('SELECT COUNT(*) as count FROM game_players WHERE player_id = $1', [playerId])
    ]);

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      ...user.rows[0],
      balance: parseFloat(user.rows[0].balance),
      transactionCount: parseInt(txCount.rows[0].count),
      gameCount: parseInt(gameCount.rows[0].count)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/users/:playerId/verify', async (req, res) => {
  try {
    const { playerId } = req.params;

    await pool.query(
      'UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE player_id = $1',
      [playerId]
    );

    res.json({ success: true, message: 'User verified' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to verify user' });
  }
});

app.put('/users/:playerId/balance', async (req, res) => {
  try {
    const { playerId } = req.params;
    const { amount, reason } = req.body;

    await pool.query('BEGIN');

    await pool.query(
      'UPDATE users SET balance = balance + $1, updated_at = NOW() WHERE player_id = $2',
      [amount, playerId]
    );

    await pool.query(
      'INSERT INTO transactions (player_id, type, amount, status, memo) VALUES ($1, $2, $3, $4, $5)',
      [playerId, amount > 0 ? 'DEPOSIT' : 'WITHDRAW', Math.abs(amount), 'confirmed', `Admin adjustment: ${reason}`]
    );

    await pool.query('COMMIT');

    res.json({ success: true, message: 'Balance updated' });
  } catch (error) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

// ==================== GAMES MANAGEMENT ====================
app.get('/games', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const status = req.query.status;

    let query = 'SELECT * FROM games';
    const params = [];

    if (status) {
      query += ' WHERE status = $1';
      params.push(status);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({
      games: result.rows.map(g => ({
        gameId: g.game_id,
        gameType: g.game_type,
        stake: parseFloat(g.stake),
        pot: parseFloat(g.pot),
        maxPlayers: g.max_players,
        currentPlayers: g.current_players,
        status: g.status,
        winnerId: g.winner_id,
        hostId: g.host_id,
        startTime: g.start_time,
        endTime: g.end_time,
        createdAt: g.created_at
      })),
      limit,
      offset
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch games' });
  }
});

app.delete('/games/:gameId', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { gameId } = req.params;
    const { reason } = req.body;

    await client.query('BEGIN');

    const game = await client.query(
      'SELECT * FROM games WHERE game_id = $1',
      [gameId]
    );

    if (game.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Game not found' });
    }

    const players = await client.query(
      'SELECT player_id FROM game_players WHERE game_id = $1',
      [gameId]
    );

    const stake = parseFloat(game.rows[0].stake);

    if (stake > 0) {
      for (const p of players.rows) {
        await client.query(
          'UPDATE users SET balance = balance + $1 WHERE player_id = $2',
          [stake, p.player_id]
        );

        await client.query(
          'INSERT INTO transactions (player_id, type, amount, status, metadata) VALUES ($1, $2, $3, $4, $5)',
          [p.player_id, 'REFUND', stake, 'confirmed', JSON.stringify({ gameId, reason: reason || 'Admin cancelled' })]
        );
      }
    }

    await client.query(
      'UPDATE games SET status = $1 WHERE game_id = $2',
      ['CANCELLED', gameId]
    );

    await client.query('COMMIT');

    res.json({ success: true, message: 'Game cancelled and refunded' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to cancel game' });
  } finally {
    client.release();
  }
});

// ==================== TRANSACTIONS ====================
app.get('/transactions', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const type = req.query.type;
    const status = req.query.status;

    let query = 'SELECT * FROM transactions WHERE 1=1';
    const params = [];

    if (type) {
      query += ` AND type = $${params.length + 1}`;
      params.push(type);
    }

    if (status) {
      query += ` AND status = $${params.length + 1}`;
      params.push(status);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({
      transactions: result.rows.map(tx => ({
        txId: tx.tx_id,
        playerId: tx.player_id,
        type: tx.type,
        amount: parseFloat(tx.amount),
        status: tx.status,
        zcashTxid: tx.zcash_txid,
        confirmations: tx.confirmations,
        createdAt: tx.created_at
      })),
      limit,
      offset
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// ==================== WITHDRAWALS ====================
app.get('/withdrawals', async (req, res) => {
  try {
    const status = req.query.status || 'pending';

    const result = await pool.query(
      `SELECT wq.*, u.username 
       FROM withdrawal_queue wq
       JOIN users u ON wq.player_id = u.player_id
       WHERE wq.status = $1
       ORDER BY wq.created_at ASC`,
      [status]
    );

    res.json({
      withdrawals: result.rows.map(w => ({
        withdrawalId: w.withdrawal_id,
        playerId: w.player_id,
        username: w.username,
        amount: parseFloat(w.amount),
        toAddress: w.to_address,
        status: w.status,
        zcashTxid: w.zcash_txid,
        retryCount: w.retry_count,
        errorMessage: w.error_message,
        createdAt: w.created_at
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch withdrawals' });
  }
});

app.post('/withdrawals/:withdrawalId/cancel', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { withdrawalId } = req.params;
    const { reason } = req.body;

    await client.query('BEGIN');

    const withdrawal = await client.query(
      'SELECT * FROM withdrawal_queue WHERE withdrawal_id = $1',
      [withdrawalId]
    );

    if (withdrawal.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Withdrawal not found' });
    }

    const w = withdrawal.rows[0];

    if (w.status === 'completed') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Cannot cancel completed withdrawal' });
    }

    await client.query(
      'UPDATE withdrawal_queue SET status = $1, error_message = $2 WHERE withdrawal_id = $3',
      ['cancelled', reason || 'Cancelled by admin', withdrawalId]
    );

    const refundAmount = parseFloat(w.amount) + parseFloat(process.env.WITHDRAWAL_FEE || 0.0001);

    await client.query(
      'UPDATE users SET balance = balance + $1 WHERE player_id = $2',
      [refundAmount, w.player_id]
    );

    await client.query(
      'UPDATE transactions SET status = $1 WHERE player_id = $2 AND type = $3 AND amount = $4 AND status = $5',
      ['cancelled', w.player_id, 'WITHDRAW', w.amount, 'pending']
    );

    await client.query('COMMIT');

    res.json({ success: true, message: 'Withdrawal cancelled and refunded' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to cancel withdrawal' });
  } finally {
    client.release();
  }
});

// ==================== MONITORING ====================
app.get('/monitoring/stats', async (req, res) => {
  try {
    const response = await axios.get(`${SERVICES.MONITOR}/stats`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch monitoring stats' });
  }
});

app.post('/monitoring/trigger-deposits', async (req, res) => {
  try {
    const response = await axios.post(`${SERVICES.MONITOR}/trigger-deposits`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to trigger deposit monitoring' });
  }
});

app.post('/monitoring/trigger-withdrawals', async (req, res) => {
  try {
    const response = await axios.post(`${SERVICES.MONITOR}/trigger-withdrawals`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to trigger withdrawal processing' });
  }
});

// ==================== LOGS ====================
app.get('/logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const action = req.query.action;

    let query = 'SELECT * FROM admin_logs';
    const params = [];

    if (action) {
      query += ' WHERE action = $1';
      params.push(action);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const result = await pool.query(query, params);

    res.json({ logs: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

app.post('/logs', async (req, res) => {
  try {
    const { action, details } = req.body;

    await pool.query(
      'INSERT INTO admin_logs (admin_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
      ['ADMIN', action, JSON.stringify(details), req.ip]
    );

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create log' });
  }
});

// ==================== PLATFORM STATS ====================
app.get('/stats/platform', async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM users WHERE is_verified = TRUE) as verified_users,
        (SELECT COUNT(*) FROM users WHERE last_login > NOW() - INTERVAL '24 hours') as active_24h,
        (SELECT COUNT(*) FROM games) as total_games,
        (SELECT COUNT(*) FROM games WHERE status = 'COMPLETED') as completed_games,
        (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'DEPOSIT' AND status = 'confirmed') as total_deposits,
        (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'WITHDRAW' AND status IN ('confirmed', 'confirming')) as total_withdrawals,
        (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'FEE') as total_fees,
        (SELECT COALESCE(SUM(balance), 0) FROM users) as total_user_balance
    `);

    res.json(stats.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch platform stats' });
  }
});

// ==================== HEALTH ====================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();

    const services = await Promise.allSettled([
      axios.get(`${SERVICES.AUTH}/health`, { timeout: 2000 }),
      axios.get(`${SERVICES.WALLET}/health`, { timeout: 2000 }),
      axios.get(`${SERVICES.GAME}/health`, { timeout: 2000 }),
      axios.get(`${SERVICES.MONITOR}/health`, { timeout: 2000 })
    ]);

    res.json({
      status: 'healthy',
      service: 'admin',
      services: {
        auth: services[0].status === 'fulfilled' ? 'healthy' : 'unhealthy',
        wallet: services[1].status === 'fulfilled' ? 'healthy' : 'unhealthy',
        game: services[2].status === 'fulfilled' ? 'healthy' : 'unhealthy',
        monitor: services[3].status === 'fulfilled' ? 'healthy' : 'unhealthy'
      }
    });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`👑 Admin Controller running on port ${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json(buildErrorResponse(5006, {
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  }));
});

module.exports = app;