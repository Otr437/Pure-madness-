// ==================== GAME MICROSERVICE ====================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const Redis = require('ioredis');
const { WebSocketServer } = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const PORT = process.env.GAME_PORT || 3004;

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

const HOUSE_EDGE = parseFloat(process.env.HOUSE_EDGE) || 0.10;
const MAX_GAME_STAKE = parseFloat(process.env.MAX_GAME_STAKE) || 10;
const MIN_GAME_STAKE = parseFloat(process.env.MIN_GAME_STAKE) || 0.001;

// ==================== ERROR HANDLING ====================
const ERROR_CODES = {
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
  INSUFFICIENT_BALANCE: 2000,
  ACCOUNT_NOT_VERIFIED: 2003,
  USER_NOT_FOUND: 1005
};

function buildErrorResponse(errorCode, details = {}) {
  const errors = {
    [ERROR_CODES.GAME_NOT_FOUND]: {
      message: 'Game not found',
      userMessage: 'This game no longer exists or has already ended.',
      action: 'Browse available games or create a new one'
    },
    [ERROR_CODES.GAME_FULL]: {
      message: 'Game is full',
      userMessage: `This game has ${details.currentPlayers}/${details.maxPlayers} players and is full.`,
      action: 'Find another game or create your own'
    },
    [ERROR_CODES.GAME_ALREADY_STARTED]: {
      message: 'Game already started',
      userMessage: 'This game has already begun and cannot accept new players.',
      action: 'Join a different game that\'s waiting for players'
    },
    [ERROR_CODES.PLAYER_ALREADY_IN_GAME]: {
      message: 'Already in a game',
      userMessage: 'You\'re already in an active game.',
      action: 'Complete your current game before joining another'
    },
    [ERROR_CODES.INVALID_GAME_TYPE]: {
      message: 'Invalid game type',
      userMessage: `Game type "${details.provided}" is not valid.`,
      action: 'Choose from: PICTURE_RUSH, PICTURE_MATCH, QUICK_DRAW'
    },
    [ERROR_CODES.STAKE_TOO_LOW]: {
      message: 'Stake too low',
      userMessage: `Minimum game stake is ${details.min} ZEC. You tried ${details.provided} ZEC.`,
      action: 'Increase the stake amount'
    },
    [ERROR_CODES.STAKE_TOO_HIGH]: {
      message: 'Stake too high',
      userMessage: `Maximum game stake is ${details.max} ZEC. You tried ${details.provided} ZEC.`,
      action: 'Reduce the stake amount'
    },
    [ERROR_CODES.NOT_IN_GAME]: {
      message: 'Not in this game',
      userMessage: 'You\'re not a player in this game.',
      action: 'Join the game first before performing actions'
    },
    [ERROR_CODES.INSUFFICIENT_BALANCE]: {
      message: 'Insufficient balance',
      userMessage: `You need ${details.required} ZEC but only have ${details.available} ZEC.`,
      action: 'Deposit more ZEC to play'
    },
    [ERROR_CODES.ACCOUNT_NOT_VERIFIED]: {
      message: 'Account not verified',
      userMessage: 'You need to verify your account to play staked games.',
      action: 'Complete account verification'
    },
    [ERROR_CODES.USER_NOT_FOUND]: {
      message: 'User not found',
      userMessage: 'Your account could not be found.',
      action: 'Please log in again'
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

// ==================== GAME STATE ====================
const activeGames = new Map();
const playerGameMap = new Map();
const wsClients = new Map();

class GameSession {
  constructor(gameId, gameType, stake, maxPlayers, hostId) {
    this.gameId = gameId;
    this.gameType = gameType;
    this.stake = stake;
    this.maxPlayers = maxPlayers;
    this.hostId = hostId;
    this.players = new Map();
    this.status = 'WAITING';
    this.pot = stake;
    this.currentRound = 0;
    this.scores = new Map();
    this.startTime = null;
    this.roundStartTime = null;
    this.gameData = this.initGameData(gameType);
    this.timer = null;
  }

  initGameData(gameType) {
    switch (gameType) {
      case 'PICTURE_RUSH':
        return {
          totalRounds: 5,
          roundDuration: 30000,
          images: [],
          submissions: new Map()
        };
      case 'PICTURE_MATCH':
        return {
          totalRounds: 10,
          roundDuration: 15000,
          pairs: [],
          revealed: new Set(),
          matched: new Set()
        };
      case 'QUICK_DRAW':
        return {
          totalRounds: 8,
          roundDuration: 20000,
          drawings: new Map(),
          votes: new Map()
        };
      default:
        return {};
    }
  }

  addPlayer(playerId, playerData) {
    this.players.set(playerId, {
      playerId,
      username: playerData.username,
      avatarId: playerData.avatarId,
      score: 0,
      connected: true,
      position: this.players.size
    });
    this.scores.set(playerId, 0);
    this.pot += this.stake;
    playerGameMap.set(playerId, this.gameId);
  }

  addScore(playerId, points) {
    const currentScore = this.scores.get(playerId) || 0;
    this.scores.set(playerId, currentScore + points);
    const player = this.players.get(playerId);
    if (player) player.score = currentScore + points;
  }

  getLeaderboard() {
    return Array.from(this.scores.entries())
      .map(([playerId, score]) => ({
        playerId,
        username: this.players.get(playerId)?.username,
        score
      }))
      .sort((a, b) => b.score - a.score);
  }

  getWinner() {
    const leaderboard = this.getLeaderboard();
    return leaderboard.length > 0 ? leaderboard[0].playerId : null;
  }

  isFull() {
    return this.players.size >= this.maxPlayers;
  }

  toJSON() {
    return {
      gameId: this.gameId,
      gameType: this.gameType,
      stake: this.stake,
      maxPlayers: this.maxPlayers,
      currentPlayers: this.players.size,
      hostId: this.hostId,
      status: this.status,
      pot: this.pot,
      currentRound: this.currentRound,
      players: Array.from(this.players.values()),
      scores: Array.from(this.scores.entries()).map(([id, score]) => ({ playerId: id, score }))
    };
  }
}

// ==================== PICTURE RUSH ====================
const PICTURE_RUSH_IMAGES = [
  { id: 1, url: 'mountain', options: ['Mountain', 'Ocean', 'Desert', 'Forest'], correct: 0 },
  { id: 2, url: 'city', options: ['Paris', 'Tokyo', 'New York', 'London'], correct: 2 },
  { id: 3, url: 'tiger', options: ['Lion', 'Tiger', 'Leopard', 'Cheetah'], correct: 1 },
  { id: 4, url: 'sushi', options: ['Sushi', 'Pizza', 'Burger', 'Pasta'], correct: 0 },
  { id: 5, url: 'soccer', options: ['Soccer', 'Basketball', 'Tennis', 'Baseball'], correct: 0 }
];

async function startPictureRush(game) {
  console.log(`🎮 Starting PICTURE RUSH: ${game.gameId}`);
  
  const shuffled = [...PICTURE_RUSH_IMAGES].sort(() => Math.random() - 0.5);
  game.gameData.images = shuffled.slice(0, game.gameData.totalRounds);
  
  game.status = 'IN_PROGRESS';
  game.startTime = Date.now();
  game.currentRound = 0;
  
  await pool.query(
    'UPDATE games SET status = $1, start_time = NOW() WHERE game_id = $2',
    ['IN_PROGRESS', game.gameId]
  );

  broadcastToGame(game.gameId, {
    type: 'GAME_STARTED',
    gameType: 'PICTURE_RUSH',
    totalRounds: game.gameData.totalRounds
  });

  setTimeout(() => startPictureRushRound(game), 3000);
}

async function startPictureRushRound(game) {
  if (game.currentRound >= game.gameData.totalRounds) {
    return endGame(game);
  }

  game.currentRound++;
  game.roundStartTime = Date.now();
  const image = game.gameData.images[game.currentRound - 1];
  game.gameData.currentImage = image;
  game.gameData.submissions.clear();

  broadcastToGame(game.gameId, {
    type: 'ROUND_START',
    round: game.currentRound,
    totalRounds: game.gameData.totalRounds,
    imageUrl: image.url,
    options: image.options,
    duration: game.gameData.roundDuration
  });

  game.timer = setTimeout(() => endPictureRushRound(game), game.gameData.roundDuration);
}

async function submitPictureRushAnswer(game, playerId, answer) {
  if (game.gameData.submissions.has(playerId)) {
    return { success: false, error: 'Already submitted' };
  }

  const image = game.gameData.currentImage;
  const responseTime = Date.now() - game.roundStartTime;
  const isCorrect = answer === image.correct;

  let points = 0;
  if (isCorrect) {
    const speedBonus = Math.max(0, 50 - Math.floor(responseTime / 600));
    points = 100 + speedBonus;
    game.addScore(playerId, points);
  }

  game.gameData.submissions.set(playerId, { answer, responseTime, isCorrect, points });

  if (game.gameData.submissions.size === game.players.size) {
    clearTimeout(game.timer);
    endPictureRushRound(game);
  }

  return { success: true, isCorrect, points };
}

async function endPictureRushRound(game) {
  const image = game.gameData.currentImage;
  const results = Array.from(game.gameData.submissions.entries()).map(([playerId, data]) => ({
    playerId,
    answer: data.answer,
    isCorrect: data.isCorrect,
    points: data.points
  }));

  broadcastToGame(game.gameId, {
    type: 'ROUND_END',
    round: game.currentRound,
    correctAnswer: image.correct,
    results,
    leaderboard: game.getLeaderboard()
  });

  setTimeout(() => startPictureRushRound(game), 5000);
}

// ==================== PICTURE MATCH ====================
async function startPictureMatch(game) {
  console.log(`🎮 Starting PICTURE MATCH: ${game.gameId}`);
  
  const emojis = ['🍎', '🚗', '⚽', '🎸', '🌟', '🐶', '🏠', '📱', '🎨', '🌈'];
  const pairs = [...emojis, ...emojis].sort(() => Math.random() - 0.5);
  
  game.gameData.pairs = pairs.map((emoji, index) => ({ id: index, emoji, matched: false }));
  game.status = 'IN_PROGRESS';
  game.startTime = Date.now();
  
  await pool.query(
    'UPDATE games SET status = $1, start_time = NOW() WHERE game_id = $2',
    ['IN_PROGRESS', game.gameId]
  );

  broadcastToGame(game.gameId, {
    type: 'GAME_STARTED',
    gameType: 'PICTURE_MATCH',
    gridSize: game.gameData.pairs.length
  });

  startPictureMatchRound(game);
}

async function startPictureMatchRound(game) {
  game.currentRound++;
  game.roundStartTime = Date.now();

  broadcastToGame(game.gameId, {
    type: 'ROUND_START',
    round: game.currentRound,
    pairs: game.gameData.pairs.map(p => ({ id: p.id, matched: p.matched })),
    duration: game.gameData.roundDuration
  });

  game.timer = setTimeout(() => endGame(game), game.gameData.roundDuration);
}

async function flipPictureMatchCard(game, playerId, cardId) {
  const card = game.gameData.pairs.find(p => p.id === cardId);
  if (!card || card.matched) {
    return { success: false, error: 'Invalid card' };
  }

  game.gameData.revealed.add(cardId);

  broadcastToGame(game.gameId, {
    type: 'CARD_FLIPPED',
    playerId,
    cardId,
    emoji: card.emoji
  });

  if (game.gameData.revealed.size === 2) {
    const revealedIds = Array.from(game.gameData.revealed);
    const card1 = game.gameData.pairs.find(p => p.id === revealedIds[0]);
    const card2 = game.gameData.pairs.find(p => p.id === revealedIds[1]);

    if (card1.emoji === card2.emoji) {
      card1.matched = true;
      card2.matched = true;
      game.gameData.matched.add(revealedIds[0]);
      game.gameData.matched.add(revealedIds[1]);
      game.addScore(playerId, 50);

      broadcastToGame(game.gameId, {
        type: 'MATCH_FOUND',
        playerId,
        cardIds: revealedIds,
        points: 50
      });

      if (game.gameData.matched.size === game.gameData.pairs.length) {
        clearTimeout(game.timer);
        endGame(game);
      }
    } else {
      setTimeout(() => {
        broadcastToGame(game.gameId, {
          type: 'CARDS_HIDDEN',
          cardIds: revealedIds
        });
      }, 1000);
    }

    game.gameData.revealed.clear();
  }

  return { success: true };
}

// ==================== QUICK DRAW ====================
const QUICK_DRAW_WORDS = ['cat', 'dog', 'house', 'tree', 'car', 'sun', 'moon', 'star'];

async function startQuickDraw(game) {
  console.log(`🎮 Starting QUICK DRAW: ${game.gameId}`);
  
  game.status = 'IN_PROGRESS';
  game.startTime = Date.now();
  game.currentRound = 0;
  
  await pool.query(
    'UPDATE games SET status = $1, start_time = NOW() WHERE game_id = $2',
    ['IN_PROGRESS', game.gameId]
  );

  broadcastToGame(game.gameId, {
    type: 'GAME_STARTED',
    gameType: 'QUICK_DRAW',
    totalRounds: game.gameData.totalRounds
  });

  setTimeout(() => startQuickDrawRound(game), 3000);
}

async function startQuickDrawRound(game) {
  if (game.currentRound >= game.gameData.totalRounds) {
    return endGame(game);
  }

  game.currentRound++;
  game.roundStartTime = Date.now();
  
  const word = QUICK_DRAW_WORDS[Math.floor(Math.random() * QUICK_DRAW_WORDS.length)];
  game.gameData.targetWord = word;
  game.gameData.drawings.clear();
  game.gameData.votes.clear();

  for (const playerId of game.players.keys()) {
    broadcastToPlayer(playerId, {
      type: 'ROUND_START',
      round: game.currentRound,
      word: word,
      duration: game.gameData.roundDuration
    });
  }

  game.timer = setTimeout(() => startQuickDrawVoting(game), game.gameData.roundDuration);
}

async function submitQuickDrawing(game, playerId, drawingData) {
  if (game.gameData.drawings.has(playerId)) {
    return { success: false, error: 'Already submitted' };
  }

  game.gameData.drawings.set(playerId, { data: drawingData, submitTime: Date.now() - game.roundStartTime });

  if (game.gameData.drawings.size === game.players.size) {
    clearTimeout(game.timer);
    startQuickDrawVoting(game);
  }

  return { success: true };
}

async function startQuickDrawVoting(game) {
  const drawings = Array.from(game.gameData.drawings.entries()).map(([playerId, data]) => ({
    playerId,
    data: data.data
  }));

  broadcastToGame(game.gameId, {
    type: 'VOTING_START',
    drawings,
    duration: 15000
  });

  game.timer = setTimeout(() => endQuickDrawRound(game), 15000);
}

async function submitQuickDrawVote(game, voterId, targetPlayerId) {
  if (voterId === targetPlayerId) {
    return { success: false, error: 'Cannot vote for yourself' };
  }

  game.gameData.votes.set(voterId, targetPlayerId);

  if (game.gameData.votes.size === game.players.size) {
    clearTimeout(game.timer);
    endQuickDrawRound(game);
  }

  return { success: true };
}

async function endQuickDrawRound(game) {
  const voteCounts = new Map();
  for (const targetId of game.gameData.votes.values()) {
    voteCounts.set(targetId, (voteCounts.get(targetId) || 0) + 1);
  }

  for (const [playerId, votes] of voteCounts.entries()) {
    game.addScore(playerId, votes * 25);
  }

  broadcastToGame(game.gameId, {
    type: 'ROUND_END',
    round: game.currentRound,
    word: game.gameData.targetWord,
    votes: Array.from(voteCounts.entries()).map(([id, count]) => ({ playerId: id, votes: count })),
    leaderboard: game.getLeaderboard()
  });

  setTimeout(() => startQuickDrawRound(game), 5000);
}

// ==================== END GAME ====================
async function endGame(game) {
  game.status = 'COMPLETED';
  const winnerId = game.getWinner();
  const winnings = parseFloat(game.pot) * (1 - HOUSE_EDGE);
  const houseFee = parseFloat(game.pot) * HOUSE_EDGE;

  console.log(`🏁 Game ${game.gameId} completed - Winner: ${winnerId}`);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      'UPDATE games SET status = $1, winner_id = $2, end_time = NOW() WHERE game_id = $3',
      ['COMPLETED', winnerId, game.gameId]
    );

    if (winnings > 0 && winnerId) {
      await client.query(
        'UPDATE users SET balance = balance + $1, updated_at = NOW() WHERE player_id = $2',
        [winnings, winnerId]
      );

      await client.query(
        'INSERT INTO transactions (player_id, type, amount, status, metadata) VALUES ($1, $2, $3, $4, $5)',
        [winnerId, 'WIN', winnings, 'confirmed', JSON.stringify({ gameId: game.gameId })]
      );
    }

    if (houseFee > 0) {
      await client.query(
        'INSERT INTO transactions (player_id, type, amount, status, metadata) VALUES ($1, $2, $3, $4, $5)',
        ['HOUSE', 'FEE', houseFee, 'confirmed', JSON.stringify({ gameId: game.gameId })]
      );
    }

    await client.query('COMMIT');

    broadcastToGame(game.gameId, {
      type: 'GAME_ENDED',
      winnerId,
      winnings,
      houseFee,
      leaderboard: game.getLeaderboard()
    });

    for (const playerId of game.players.keys()) {
      playerGameMap.delete(playerId);
    }
    activeGames.delete(game.gameId);

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error ending game:', error);
  } finally {
    client.release();
  }
}

// ==================== WEBSOCKET ====================
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const playerId = url.searchParams.get('playerId');
  
  if (!playerId) {
    ws.close(1008, 'Player ID required');
    return;
  }
  
  wsClients.set(playerId, ws);
  console.log(`🔌 Player connected: ${playerId}`);
  
  ws.send(JSON.stringify({ type: 'CONNECTED', playerId }));

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);
      await handleMessage(playerId, message);
    } catch (error) {
      console.error('Message error:', error);
    }
  });

  ws.on('close', () => {
    wsClients.delete(playerId);
    console.log(`🔌 Player disconnected: ${playerId}`);
  });
});

async function handleMessage(playerId, message) {
  const gameId = playerGameMap.get(playerId);
  const game = activeGames.get(gameId);

  if (!game) return;

  switch (message.type) {
    case 'SUBMIT_ANSWER':
      if (game.gameType === 'PICTURE_RUSH') {
        const result = await submitPictureRushAnswer(game, playerId, message.answer);
        broadcastToPlayer(playerId, { type: 'ANSWER_RESULT', ...result });
      }
      break;

    case 'FLIP_CARD':
      if (game.gameType === 'PICTURE_MATCH') {
        await flipPictureMatchCard(game, playerId, message.cardId);
      }
      break;

    case 'SUBMIT_DRAWING':
      if (game.gameType === 'QUICK_DRAW') {
        await submitQuickDrawing(game, playerId, message.drawing);
      }
      break;

    case 'VOTE':
      if (game.gameType === 'QUICK_DRAW') {
        await submitQuickDrawVote(game, playerId, message.targetPlayerId);
      }
      break;
  }
}

function broadcastToGame(gameId, data) {
  const game = activeGames.get(gameId);
  if (!game) return;

  for (const playerId of game.players.keys()) {
    broadcastToPlayer(playerId, data);
  }
}

function broadcastToPlayer(playerId, data) {
  const client = wsClients.get(playerId);
  if (client && client.readyState === 1) {
    try {
      client.send(JSON.stringify(data));
    } catch (error) {
      console.error(`Failed to send to ${playerId}:`, error);
    }
  }
}

// ==================== API ROUTES ====================

app.post('/create', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { playerId, gameType, stake, maxPlayers } = req.body;

    if (!['PICTURE_RUSH', 'PICTURE_MATCH', 'QUICK_DRAW'].includes(gameType)) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.INVALID_GAME_TYPE, {
        provided: gameType,
        validTypes: ['PICTURE_RUSH', 'PICTURE_MATCH', 'QUICK_DRAW']
      }));
    }

    if (stake < MIN_GAME_STAKE) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.STAKE_TOO_LOW, {
        provided: stake,
        min: MIN_GAME_STAKE
      }));
    }

    if (stake > MAX_GAME_STAKE) {
      return res.status(400).json(buildErrorResponse(ERROR_CODES.STAKE_TOO_HIGH, {
        provided: stake,
        max: MAX_GAME_STAKE
      }));
    }

    if (playerGameMap.has(playerId)) {
      const existingGameId = playerGameMap.get(playerId);
      return res.status(400).json(buildErrorResponse(ERROR_CODES.PLAYER_ALREADY_IN_GAME, {
        currentGameId: existingGameId
      }));
    }

    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT balance, is_verified, username, avatar_id FROM users WHERE player_id = $1 FOR UPDATE',
      [playerId]
    );

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json(buildErrorResponse(ERROR_CODES.USER_NOT_FOUND, {
        playerId
      }));
    }

    const user = userResult.rows[0];

    if (stake > 0 && !user.is_verified) {
      await client.query('ROLLBACK');
      return res.status(403).json(buildErrorResponse(ERROR_CODES.ACCOUNT_NOT_VERIFIED, {
        stakeAmount: stake
      }));
    }

    if (parseFloat(user.balance) < stake) {
      await client.query('ROLLBACK');
      return res.status(400).json(buildErrorResponse(ERROR_CODES.INSUFFICIENT_BALANCE, {
        required: stake,
        available: parseFloat(user.balance)
      }));
    }

    if (stake > 0) {
      await client.query(
        'UPDATE users SET balance = balance - $1, updated_at = NOW() WHERE player_id = $2',
        [stake, playerId]
      );
    }

    const gameResult = await client.query(
      `INSERT INTO games (game_type, stake, max_players, host_id, status, pot, current_players)
       VALUES ($1, $2, $3, $4, 'WAITING', $2, 1)
       RETURNING game_id`,
      [gameType, stake, maxPlayers, playerId]
    );

    const gameId = gameResult.rows[0].game_id;

    await client.query(
      'INSERT INTO game_players (game_id, player_id, position) VALUES ($1, $2, 0)',
      [gameId, playerId]
    );

    if (stake > 0) {
      await client.query(
        'INSERT INTO transactions (player_id, type, amount, status, metadata) VALUES ($1, $2, $3, $4, $5)',
        [playerId, 'LOSE', stake, 'confirmed', JSON.stringify({ gameId, action: 'game_entry' })]
      );
    }

    await client.query('COMMIT');

    const game = new GameSession(gameId, gameType, stake, maxPlayers, playerId);
    game.addPlayer(playerId, user);
    activeGames.set(gameId, game);

    console.log(`✅ Game created: ${gameId} (${gameType})`);

    res.json({ 
      success: true, 
      gameId, 
      game: game.toJSON(),
      message: 'Game created successfully. Waiting for players...',
      nextStep: 'Share game ID or wait for players to join'
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Game creation error:', error);
    res.status(500).json(buildErrorResponse(5006, {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Failed to create game'
    }));
  } finally {
    client.release();
  }
});

app.post('/join', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { playerId, gameId } = req.body;

    if (playerGameMap.has(playerId)) {
      return res.status(400).json({ error: 'Already in a game' });
    }

    const game = activeGames.get(gameId);
    if (!game || game.status !== 'WAITING') {
      return res.status(404).json({ error: 'Game not found or started' });
    }

    if (game.isFull()) {
      return res.status(400).json({ error: 'Game is full' });
    }

    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT balance, is_verified, username, avatar_id FROM users WHERE player_id = $1 FOR UPDATE',
      [playerId]
    );

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    if (game.stake > 0 && !user.is_verified) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Must verify account' });
    }

    if (parseFloat(user.balance) < game.stake) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    if (game.stake > 0) {
      await client.query(
        'UPDATE users SET balance = balance - $1, updated_at = NOW() WHERE player_id = $2',
        [game.stake, playerId]
      );
    }

    await client.query(
      'INSERT INTO game_players (game_id, player_id, position) VALUES ($1, $2, $3)',
      [gameId, playerId, game.players.size]
    );

    await client.query(
      'UPDATE games SET current_players = current_players + 1, pot = pot + $1 WHERE game_id = $2',
      [game.stake, gameId]
    );

    if (game.stake > 0) {
      await client.query(
        'INSERT INTO transactions (player_id, type, amount, status, metadata) VALUES ($1, $2, $3, $4, $5)',
        [playerId, 'LOSE', game.stake, 'confirmed', JSON.stringify({ gameId, action: 'game_entry' })]
      );
    }

    await client.query('COMMIT');

    game.addPlayer(playerId, user);

    console.log(`✅ Player ${playerId} joined game ${gameId}`);

    broadcastToGame(gameId, {
      type: 'PLAYER_JOINED',
      playerId,
      game: game.toJSON()
    });

    // Auto-start if full
    if (game.isFull()) {
      setTimeout(async () => {
        switch (game.gameType) {
          case 'PICTURE_RUSH':
            await startPictureRush(game);
            break;
          case 'PICTURE_MATCH':
            await startPictureMatch(game);
            break;
          case 'QUICK_DRAW':
            await startQuickDraw(game);
            break;
        }
      }, 3000);
    }

    res.json({ success: true, game: game.toJSON() });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Game join error:', error);
    res.status(500).json({ error: 'Failed to join game' });
  } finally {
    client.release();
  }
});

app.get('/active', async (req, res) => {
  try {
    const { gameType } = req.query;

    const games = Array.from(activeGames.values())
      .filter(g => g.status === 'WAITING')
      .filter(g => !gameType || g.gameType === gameType)
      .map(g => g.toJSON());

    res.json({ games });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch games' });
  }
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'healthy', 
      service: 'game',
      activeGames: activeGames.size,
      connectedPlayers: wsClients.size
    });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

server.listen(PORT, () => {
  console.log(`🎮 Game Service running on port ${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json(buildErrorResponse(5006, {
    message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
  }));
});

module.exports = app;