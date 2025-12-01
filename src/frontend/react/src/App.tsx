
import React, { createContext, useContext, useState, useEffect } from 'react';
import { Home, Gamepad2, Wallet as WalletIcon, User, Trophy, ChevronLeft, Eye, EyeOff, Shield, Copy, AlertCircle, CheckCircle, XCircle, ArrowDownLeft, ArrowUpRight, Zap, LogOut, Timer, Brain, Coins, Users, Lock, Loader2, RefreshCw, Send, Crown, MessageSquare, Search, Calendar, LifeBuoy, ChevronUp, ChevronDown, Edit3, TrendingUp, TrendingDown, Minus, Sword, MapPin, Clock as ClockIcon, ArrowRight, Star, Award, Target, Plus, X } from 'lucide-react';

// ==================== CONFIGURATION ====================
const API_URL = 'http://localhost:3001/api';

// ==================== HERO AVATARS ====================
const HEROES = [
  { id: 'hero_1', name: 'Shadow', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=shadow' },
  { id: 'hero_2', name: 'Phantom', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=phantom' },
  { id: 'hero_3', name: 'Ghost', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ghost' },
  { id: 'hero_4', name: 'Ninja', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ninja' },
  { id: 'hero_5', name: 'Raven', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=raven' },
  { id: 'hero_6', name: 'Viper', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=viper' },
  { id: 'hero_7', name: 'Specter', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=specter' },
  { id: 'hero_8', name: 'Wraith', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=wraith' },
  { id: 'hero_9', name: 'Eclipse', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=eclipse' },
  { id: 'hero_10', name: 'Void', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=void' },
  { id: 'hero_11', name: 'Cipher', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=cipher' },
  { id: 'hero_12', name: 'Matrix', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=matrix' },
  { id: 'hero_13', name: 'Quantum', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=quantum' },
  { id: 'hero_14', name: 'Nexus', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=nexus' },
  { id: 'hero_15', name: 'Pulse', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=pulse' },
  { id: 'hero_16', name: 'Vertex', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=vertex' },
  { id: 'hero_17', name: 'Zenith', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=zenith' },
  { id: 'hero_18', name: 'Apex', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=apex' },
];

const getHeroImage = (id) => HEROES.find(h => h.id === id)?.url || HEROES[0].url;

// ==================== API CLIENT ====================
const api = {
  async request(endpoint, options = {}) {
    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Request failed');
    return data;
  },

  auth: {
    signup: (password) => api.request('/auth/signup', { method: 'POST', body: JSON.stringify({ password }) }),
    login: (playerId, password) => api.request('/auth/login', { method: 'POST', body: JSON.stringify({ playerId, password }) }),
  },

  games: {
    create: (type, stake, maxPlayers, playerId) => api.request('/games/create', { method: 'POST', body: JSON.stringify({ type, stake, maxPlayers, playerId }) }),
    join: (roomId, playerId) => api.request('/games/join', { method: 'POST', body: JSON.stringify({ roomId, playerId }) }),
    getRooms: (gameType) => api.request(`/games/rooms/${gameType}`),
    pictureRush: {
      start: (playerId, roomId) => api.request('/games/picture-rush/start', { method: 'POST', body: JSON.stringify({ playerId, roomId }) }),
      answer: (gameId, playerId, answer, round) => api.request('/games/picture-rush/answer', { method: 'POST', body: JSON.stringify({ gameId, playerId, answer, round }) }),
    },
    pictureMatch: {
      start: () => api.request('/games/picture-match/start', { method: 'POST' }),
    }
  },

  wallet: {
    deposit: (playerId, amount) => api.request('/wallet/deposit', { method: 'POST', body: JSON.stringify({ playerId, amount }) }),
    withdraw: (playerId, amount, address) => api.request('/wallet/withdraw', { method: 'POST', body: JSON.stringify({ playerId, amount, address }) }),
    getTransactions: (playerId) => api.request(`/wallet/transactions/${playerId}`),
  },

  profile: {
    verify: (playerId, txId) => api.request('/profile/verify', { method: 'POST', body: JSON.stringify({ playerId, txId }) }),
    updateAvatar: (playerId, avatarId) => api.request('/profile/avatar', { method: 'POST', body: JSON.stringify({ playerId, avatarId }) }),
    updateUsername: (playerId, username) => api.request('/profile/username', { method: 'POST', body: JSON.stringify({ playerId, username }) }),
  },

  events: () => api.request('/events'),
  leaderboard: () => api.request('/leaderboard'),
  support: {
    faq: () => api.request('/support/faq'),
    ticket: (playerId, issue, description) => api.request('/support/ticket', { method: 'POST', body: JSON.stringify({ playerId, issue, description }) }),
  },
  stats: () => api.request('/stats/room-stats'),
};

// ==================== STORE CONTEXT ====================
const StoreContext = createContext(null);

const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) throw new Error('useStore must be used within StoreProvider');
  return context;
};

const StoreProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [currentPage, setCurrentPage] = useState('landing');
  const [transactions, setTransactions] = useState([]);
  const [rooms, setRooms] = useState([]);
  const [events, setEvents] = useState([]);
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeGame, setActiveGame] = useState(null);
  const [hideBalance, setHideBalance] = useState(false);
  const [faqs, setFaqs] = useState([]);

  const signup = async (password) => {
    try {
      setLoading(true);
      const data = await api.auth.signup(password);
      if (data.success) {
        setUser(data.user);
        setCurrentPage('home');
        return true;
      }
      return false;
    } catch (error) {
      console.error('Signup failed:', error);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const login = async (playerId, password) => {
    try {
      setLoading(true);
      const data = await api.auth.login(playerId, password);
      if (data.success) {
        setUser(data.user);
        loadUserData(data.user.playerId);
        setCurrentPage('home');
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const loadUserData = async (playerId) => {
    try {
      const txs = await api.wallet.getTransactions(playerId);
      setTransactions(txs);
    } catch (error) {
      console.error('Failed to load user data:', error);
    }
  };

  const logout = () => {
    setUser(null);
    setCurrentPage('landing');
    setTransactions([]);
  };

  const navigate = (page, data) => {
    setCurrentPage(page);
    if (data?.game) setActiveGame(data.game);
  };

  const deposit = async (amount) => {
    try {
      const result = await api.wallet.deposit(user.playerId, amount);
      if (result.success) {
        setUser({ ...user, balance: result.newBalance });
        setTransactions([result.transaction, ...transactions]);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Deposit failed:', error);
      return false;
    }
  };

  const withdraw = async (amount, address) => {
    try {
      const result = await api.wallet.withdraw(user.playerId, amount, address);
      if (result.success) {
        setUser({ ...user, balance: result.newBalance });
        setTransactions([result.transaction, ...transactions]);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Withdraw failed:', error);
      return false;
    }
  };

  const updateUsername = async (username) => {
    try {
      const result = await api.profile.updateUsername(user.playerId, username);
      if (result.success) {
        setUser({ ...user, username });
        return true;
      }
      return false;
    } catch (error) {
      console.error('Update username failed:', error);
      return false;
    }
  };

  const updateAvatar = async (avatarId) => {
    try {
      const result = await api.profile.updateAvatar(user.playerId, avatarId);
      if (result.success) {
        setUser({ ...user, avatarId });
      }
    } catch (error) {
      console.error('Update avatar failed:', error);
    }
  };

  const verifyAccount = async (txId) => {
    try {
      const result = await api.profile.verify(user.playerId, txId);
      if (result.success) {
        setUser({ ...user, isVerified: true });
        return true;
      }
      return false;
    } catch (error) {
      console.error('Verify failed:', error);
      return false;
    }
  };

  const createGame = async (type, stake, maxPlayers) => {
    try {
      const room = await api.games.create(type, stake, maxPlayers, user.playerId);
      setActiveGame({ gameId: room.id, type, stake, maxPlayers, status: 'WAITING' });
      navigate('room');
    } catch (error) {
      console.error('Create game failed:', error);
    }
  };

  const joinGame = async (roomId) => {
    try {
      const result = await api.games.join(roomId, user.playerId);
      if (result.success) {
        const room = result.room;
        setActiveGame({ gameId: room.id, type: room.type, stake: room.stake, maxPlayers: room.maxPlayers, status: room.status });
        navigate('room');
      }
    } catch (error) {
      console.error('Join game failed:', error);
    }
  };

  const fetchRooms = async (gameType) => {
    try {
      const availableRooms = await api.games.getRooms(gameType);
      setRooms(availableRooms);
    } catch (error) {
      console.error('Fetch rooms failed:', error);
    }
  };

  const loadLeaderboard = async () => {
    try {
      const data = await api.leaderboard();
      setLeaderboardData(data);
    } catch (error) {
      console.error('Load leaderboard failed:', error);
    }
  };

  const loadEvents = async () => {
    try {
      const data = await api.events();
      setEvents(data);
    } catch (error) {
      console.error('Load events failed:', error);
    }
  };

  const loadFaqs = async () => {
    try {
      const data = await api.support.faq();
      setFaqs(data);
    } catch (error) {
      console.error('Load FAQs failed:', error);
    }
  };

  return (
    <StoreContext.Provider value={{
      user, currentPage, transactions, rooms, events, leaderboardData, loading, activeGame, hideBalance, faqs,
      signup, login, logout, navigate, deposit, withdraw, updateUsername, updateAvatar, verifyAccount,
      createGame, joinGame, fetchRooms, setHideBalance, loadLeaderboard, loadEvents, loadFaqs
    }}>
      {children}
    </StoreContext.Provider>
  );
};

// ==================== LANDING PAGE ====================
const Landing = () => {
  const { navigate } = useStore();

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden bg-[#050505]">
      <div className="absolute top-[-20%] left-[-20%] w-[80%] h-[80%] bg-yellow-500 opacity-[0.04] blur-[150px] rounded-full pointer-events-none animate-pulse"></div>
      <div className="absolute bottom-[-20%] right-[-20%] w-[80%] h-[80%] bg-purple-900 opacity-[0.06] blur-[150px] rounded-full pointer-events-none"></div>

      <div className="relative z-10 text-center w-full max-w-sm flex flex-col h-[80vh] justify-between py-12">
        <div className="flex-1 flex flex-col items-center justify-center">
          <div className="relative mb-8 group">
            <div className="absolute inset-0 bg-yellow-500 blur-2xl opacity-20 group-hover:opacity-40 transition-opacity duration-500"></div>
            <div className="relative inline-flex items-center justify-center w-24 h-24 rounded-3xl bg-gradient-to-br from-gray-900 to-black border border-white/10 shadow-2xl">
              <Zap size={48} className="text-yellow-500 fill-yellow-500" />
            </div>
          </div>

          <h1 className="text-7xl font-black tracking-tighter text-white mb-4 leading-[0.85]">
            ZEC<br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-b from-yellow-500 to-yellow-600">ARENA</span>
          </h1>

          <div className="flex items-center gap-3 text-xs font-bold tracking-[0.2em] text-gray-500 border border-white/5 px-4 py-2 rounded-full bg-white/5 backdrop-blur-sm">
            <Shield size={12} />
            <span>PRIVACY FIRST PVP</span>
          </div>
        </div>

        <div className="space-y-6 w-full">
          <button
            onClick={() => navigate('auth')}
            className="w-full py-6 rounded-2xl bg-white text-black font-black text-xl tracking-wider hover:scale-[1.02] active:scale-[0.98] transition-all shadow-[0_0_50px_rgba(255,255,255,0.15)] relative overflow-hidden group"
          >
            <span className="relative z-10">PLAY ANONYMOUSLY</span>
            <div className="absolute inset-0 bg-yellow-500 transform scale-x-0 group-hover:scale-x-100 transition-transform origin-left duration-300"></div>
          </button>

          <p className="text-[10px] text-gray-600 font-mono">
            POWERED BY ZCASH • NO EMAIL REQUIRED
          </p>
        </div>
      </div>
    </div>
  );
};

// ==================== AUTH PAGE ====================
const Auth = () => {
  const [isLogin, setIsLogin] = useState(false);
  const [playerId, setPlayerId] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { signup, login, navigate } = useStore();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        const success = await login(playerId, password);
        if (!success) setError('Invalid ID/Username or Password');
      } else {
        if (password.length < 6) {
          setError('Password must be at least 6 characters');
          setLoading(false);
          return;
        }
        const success = await signup(password);
        if (!success) setError('Signup failed');
      }
    } catch (e) {
      setError('Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative bg-[#050505]">
      <button 
        onClick={() => navigate('landing')} 
        className="absolute top-8 left-6 text-gray-500 hover:text-white transition-colors"
      >
        <ChevronLeft size={24} />
      </button>

      <div className="w-full max-w-sm">
        <div className="text-center mb-10">
          <h1 className="text-3xl font-black tracking-tighter text-white">
            {isLogin ? 'WELCOME BACK' : 'CREATE IDENTITY'}
          </h1>
          <p className="text-gray-500 mt-2 text-xs uppercase tracking-widest">
            {isLogin ? 'Enter The Arena' : 'Secure & Anonymous'}
          </p>
        </div>

        <div className="bg-gray-800 p-8 rounded-3xl shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-yellow-500 to-transparent opacity-50"></div>

          <div className="flex gap-4 mb-8">
            <button 
              onClick={() => { setIsLogin(false); setError(''); }}
              className={`flex-1 pb-2 text-sm font-bold tracking-wide transition-colors border-b-2 ${!isLogin ? 'border-yellow-500 text-white' : 'border-transparent text-gray-600 hover:text-gray-400'}`}
            >
              SIGN UP
            </button>
            <button 
              onClick={() => { setIsLogin(true); setError(''); }}
              className={`flex-1 pb-2 text-sm font-bold tracking-wide transition-colors border-b-2 ${isLogin ? 'border-yellow-500 text-white' : 'border-transparent text-gray-600 hover:text-gray-400'}`}
            >
              LOGIN
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {isLogin && (
              <div className="relative group">
                <Shield className="absolute left-4 top-3.5 text-gray-500 group-focus-within:text-yellow-500 transition-colors" size={18} />
                <input 
                  type="text" 
                  placeholder="Player ID or Username"
                  value={playerId}
                  onChange={(e) => setPlayerId(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 transition-all"
                />
              </div>
            )}

            <div className="relative group">
              <Lock className="absolute left-4 top-3.5 text-gray-500 group-focus-within:text-yellow-500 transition-colors" size={18} />
              <input 
                type={showPwd ? "text" : "password"} 
                placeholder={isLogin ? "Password" : "Create Password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 transition-all"
              />
              <button 
                type="button"
                onClick={() => setShowPwd(!showPwd)}
                className="absolute right-4 top-3.5 text-gray-500 hover:text-white transition-colors"
              >
                {showPwd ? <EyeOff size={18}/> : <Eye size={18}/>}
              </button>
            </div>

            {error && <div className="text-red-400 text-xs text-center font-medium bg-red-900/20 py-2 rounded-lg border border-red-500/20">{error}</div>}

            <button 
              type="submit"
              disabled={loading}
              className="w-full bg-yellow-500 text-black font-bold py-4 rounded-xl mt-2 hover:bg-yellow-400 hover:scale-[1.02] active:scale-[0.98] transition-all shadow-[0_0_20px_rgba(244,183,40,0.3)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Processing...' : isLogin ? 'ENTER ARENA' : 'CREATE ID & PLAY'}
            </button>
          </form>

          {!isLogin && (
            <p className="text-[10px] text-gray-500 text-center mt-6 leading-relaxed">
              By creating an ID, you agree that lost passwords can only be recovered via support.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

// ==================== HOME PAGE ====================
const HomePage = () => {
  const { user, navigate } = useStore();

  return (
    <div className="p-6 pt-8 pb-24">
      <header className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-gray-400 text-xs uppercase tracking-widest font-semibold">Welcome back</h2>
          <h1 className="text-2xl font-bold text-white">
            {user?.username || `Agent ${user?.playerId.slice(0, 6)}`}
          </h1>
        </div>
        <button onClick={() => navigate('profile')} className="w-12 h-12 rounded-full bg-gradient-to-br from-yellow-500 to-orange-600 p-[2px]">
          <div className="w-full h-full rounded-full bg-black overflow-hidden">
            <img src={getHeroImage(user?.avatarId || 'hero_1')} alt="Profile" className="w-full h-full object-cover" />
          </div>
        </button>
      </header>

      <div className="space-y-6">
        <div className="bg-gradient-to-br from-yellow-900/40 to-black p-6 rounded-3xl border border-yellow-500/20 relative overflow-hidden group">
          <div className="absolute -right-10 -top-10 w-40 h-40 bg-yellow-500/10 rounded-full blur-3xl group-hover:bg-yellow-500/20 transition-all"></div>
          <div className="relative z-10">
            <h3 className="text-3xl font-black italic text-white mb-1">PVP MODE</h3>
            <p className="text-yellow-500 font-medium mb-4">Stake ZEC. Win Big.</p>
            <button onClick={() => navigate('games')} className="inline-flex items-center gap-2 bg-white text-black px-5 py-2.5 rounded-full font-bold text-sm hover:bg-yellow-500 transition-colors">
              Play Now <ArrowRight size={16} />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-800 p-4 rounded-2xl border border-white/5 hover:border-yellow-500/30 transition-colors">
            <Zap className="text-yellow-500 mb-3" size={24} />
            <h4 className="font-bold text-sm mb-1">Fast Payouts</h4>
            <p className="text-[10px] text-gray-400">90% of the pot goes to the winner instantly.</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-2xl border border-white/5 hover:border-yellow-500/30 transition-colors">
            <Shield className="text-yellow-500 mb-3" size={24} />
            <h4 className="font-bold text-sm mb-1">Privacy First</h4>
            <p className="text-[10px] text-gray-400">No email needed. Just play.</p>
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-2xl">
          <h3 className="font-bold mb-4 flex items-center gap-2">
            <Trophy className="text-yellow-500" size={20} />
            Your Stats
          </h3>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-green-500">{user?.wins || 0}</div>
              <div className="text-xs text-gray-400">Wins</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-red-500">{user?.losses || 0}</div>
              <div className="text-xs text-gray-400">Losses</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-yellow-500">{user?.xp || 0}</div>
              <div className="text-xs text-gray-400">XP</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== GAMES PAGE ====================
const GamesPage = () => {
  const { navigate, rooms, fetchRooms, user } = useStore();
  const [selectedGame, setSelectedGame] = useState('PICTURE_RUSH');
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    fetchRooms(selectedGame);
  }, [selectedGame]);

  return (
    <div className="p-6 pt-8 pb-24">
      <div className="flex items-center gap-4 mb-6">
        <button onClick={() => navigate('home')} className="text-gray-400 hover:text-white">
          <ChevronLeft size={24} />
        </button>
        <h1 className="text-2xl font-bold">Game Modes</h1>
      </div>

      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setSelectedGame('PICTURE_RUSH')}
          className={`flex-1 py-3 rounded-xl font-bold transition-all ${selectedGame === 'PICTURE_RUSH' ? 'bg-yellow-500 text-black' : 'bg-gray-800 text-white'}`}
        >
          <Timer size={16} className="inline mr-2" />
          Picture Rush
        </button>
        <button
          onClick={() => setSelectedGame('PICTURE_MATCH')}
          className={`flex-1 py-3 rounded-xl font-bold transition-all ${selectedGame === 'PICTURE_MATCH' ? 'bg-yellow-500 text-black' : 'bg-gray-800 text-white'}`}
        >
          <Brain size={16} className="inline mr-2" />
          Picture Match
        </button>
      </div>

      <button
        onClick={() => setShowCreateModal(true)}
        className="w-full bg-gradient-to-r from-yellow-500 to-orange-500 text-black font-bold py-4 rounded-xl mb-6 hover:scale-[1.02] transition-transform"
      >
        <Plus size={20} className="inline mr-2" />
        CREATE ROOM
      </button>

      <div className="space-y-3">
        {rooms.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <Gamepad2 size={48} className="mx-auto mb-4 opacity-20" />
            <p>No active rooms. Create one!</p>
          </div>
        ) : (
          rooms.map((room) => (
            <RoomCard key={room.id} room={room} />
          ))
        )}
      </div>

      {showCreateModal && <CreateRoomModal gameType={selectedGame} onClose={() => setShowCreateModal(false)} />}
    </div>
  );
};

const RoomCard = ({ room }) => {
  const { joinGame } = useStore();

  return (
    <div className="bg-gray-800 p-4 rounded-xl border border-white/10">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full overflow-hidden bg-yellow-500">
            <img src={getHeroImage(room.hostAvatar)} alt="Host" className="w-full h-full object-cover" />
          </div>
          <div>
            <div className="font-bold">{room.hostName}</div>
            <div className="text-xs text-gray-400">{room.currentPlayers}/{room.maxPlayers} Players</div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-yellow-500 font-bold">{room.stake} ZEC</div>
          <div className="text-xs text-gray-400">Stake</div>
        </div>
      </div>
      <button
        onClick={() => joinGame(room.id)}
        className="w-full bg-yellow-500 text-black font-bold py-2 rounded-lg hover:bg-yellow-400 transition-colors"
      >
        JOIN ROOM
      </button>
    </div>
  );
};

const CreateRoomModal = ({ gameType, onClose }) => {
  const { createGame, user } = useStore();
  const [stake, setStake] = useState(0.1);
  const [maxPlayers, setMaxPlayers] = useState(2);

  const handleCreate = () => {
    if (stake > user.balance) {
      alert('Insufficient balance');
      return;
    }
    createGame(gameType, stake, maxPlayers);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold">Create Room</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X size={24} />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="text-sm text-gray-400 block mb-2">Stake Amount (ZEC)</label>
            <input
              type="number"
              step="0.01"
              min="0.01"
              value={stake}
              onChange={(e) => setStake(parseFloat(e.target.value))}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
            />
          </div>

          <div>
            <label className="text-sm text-gray-400 block mb-2">Max Players</label>
            <select
              value={maxPlayers}
              onChange={(e) => setMaxPlayers(parseInt(e.target.value))}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
            >
              <option value={2}>2 Players</option>
              <option value={4}>4 Players</option>
              <option value={6}>6 Players</option>
              <option value={8}>8 Players</option>
            </select>
          </div>

          <div className="bg-gray-900 p-4 rounded-xl">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-gray-400">Total Pot:</span>
              <span className="text-yellow-500 font-bold">{(stake * maxPlayers).toFixed(4)} ZEC</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Winner Gets (90%):</span>
              <span className="text-green-500 font-bold">{(stake * maxPlayers * 0.9).toFixed(4)} ZEC</span>
            </div>
          </div>

          <button
            onClick={handleCreate}
            className="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl hover:bg-yellow-400 transition-colors"
          >
            CREATE ROOM
          </button>
        </div>
      </div>
    </div>
  );
};

// ==================== WALLET PAGE ====================
const WalletPage = () => {
  const { user, transactions, deposit, withdraw, navigate, hideBalance, setHideBalance } = useStore();
  const [showDeposit, setShowDeposit] = useState(false);
  const [showWithdraw, setShowWithdraw] = useState(false);
  const [depositAmount, setDepositAmount] = useState('');
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [withdrawAddress, setWithdrawAddress] = useState('');

  const handleDeposit = async () => {
    const amount = parseFloat(depositAmount);
    if (amount > 0) {
      await deposit(amount);
      setShowDeposit(false);
      setDepositAmount('');
    }
  };

  const handleWithdraw = async () => {
    const amount = parseFloat(withdrawAmount);
    if (amount > 0 && withdrawAddress) {
      await withdraw(amount, withdrawAddress);
      setShowWithdraw(false);
      setWithdrawAmount('');
      setWithdrawAddress('');
    }
  };

  return (
    <div className="p-6 pt-8 pb-24">
      <div className="flex items-center gap-4 mb-6">
        <button onClick={() => navigate('home')} className="text-gray-400 hover:text-white">
          <ChevronLeft size={24} />
        </button>
        <h1 className="text-2xl font-bold">Wallet</h1>
      </div>

      <div className="bg-gray-800 p-8 rounded-2xl text-center mb-6">
        <p className="text-gray-400 text-sm mb-2">Balance</p>
        <div className="flex items-center justify-center gap-3">
          <h2 className="text-4xl font-bold">
            {hideBalance ? '****' : `${user?.balance?.toFixed(4)} ZEC`}
          </h2>
          <button onClick={() => setHideBalance(!hideBalance)} className="text-gray-500 hover:text-white">
            {hideBalance ? <Eye size={20} /> : <EyeOff size={20} />}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <button 
          onClick={() => setShowDeposit(true)}
          className="bg-green-600 p-4 rounded-xl font-bold hover:bg-green-500 transition-colors flex items-center justify-center gap-2"
        >
          <ArrowDownLeft size={20} />
          Deposit
        </button>
        <button 
          onClick={() => setShowWithdraw(true)}
          className="bg-red-600 p-4 rounded-xl font-bold hover:bg-red-500 transition-colors flex items-center justify-center gap-2"
        >
          <ArrowUpRight size={20} />
          Withdraw
        </button>
      </div>

      <div className="space-y-2">
        <h3 className="font-bold flex items-center gap-2 mb-4">
          <ClockIcon size={20} />
          Transactions
        </h3>
        {transactions.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Coins size={48} className="mx-auto mb-4 opacity-20" />
            <p>No transactions yet</p>
          </div>
        ) : (
          transactions.map((tx) => (
            <div key={tx.id} className="bg-gray-800 p-4 rounded-xl flex justify-between items-center">
              <div>
                <p className="font-bold flex items-center gap-2">
                  {tx.type === 'DEPOSIT' ? <ArrowDownLeft size={16} className="text-green-500" /> : <ArrowUpRight size={16} className="text-red-500" />}
                  {tx.type}
                </p>
                <p className="text-sm text-gray-500">{new Date(tx.createdAt).toLocaleDateString()}</p>
              </div>
              <div className="text-right">
                <p className={`font-bold ${tx.type === 'DEPOSIT' ? 'text-green-500' : 'text-red-500'}`}>
                  {tx.type === 'DEPOSIT' ? '+' : ''}{tx.amount.toFixed(4)} ZEC
                </p>
                <p className="text-xs text-gray-500">{tx.status}</p>
              </div>
            </div>
          ))
        )}
      </div>

      {showDeposit && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Deposit ZEC</h3>
            <p className="text-sm text-gray-400 mb-4">For demo purposes, enter any amount to add to your balance.</p>
            <input
              type="number"
              step="0.01"
              placeholder="Amount (ZEC)"
              value={depositAmount}
              onChange={(e) => setDepositAmount(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4 text-white"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowDeposit(false)} className="flex-1 bg-gray-700 py-3 rounded-xl hover:bg-gray-600">
                Cancel
              </button>
              <button onClick={handleDeposit} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold hover:bg-yellow-400">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {showWithdraw && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Withdraw ZEC</h3>
            <input
              type="number"
              step="0.01"
              placeholder="Amount (ZEC)"
              value={withdrawAmount}
              onChange={(e) => setWithdrawAmount(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4 text-white"
            />
            <input
              type="text"
              placeholder="ZEC Address"
              value={withdrawAddress}
              onChange={(e) => setWithdrawAddress(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4 text-white"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowWithdraw(false)} className="flex-1 bg-gray-700 py-3 rounded-xl hover:bg-gray-600">
                Cancel
              </button>
              <button onClick={handleWithdraw} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold hover:bg-yellow-400">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== PROFILE PAGE ====================
const ProfilePage = () => {
  const { user, logout, navigate, updateUsername, updateAvatar, verifyAccount } = useStore();
  const [showUsernameModal, setShowUsernameModal] = useState(false);
  const [showAvatarModal, setShowAvatarModal] = useState(false);
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [txId, setTxId] = useState('');

  const handleUpdateUsername = async () => {
    if (newUsername.trim()) {
      await updateUsername(newUsername);
      setShowUsernameModal(false);
      setNewUsername('');
    }
  };

  const handleVerify = async () => {
    if (txId.trim()) {
      await verifyAccount(txId);
      setShowVerifyModal(false);
      setTxId('');
    }
  };

  return (
    <div className="p-6 pt-8 pb-24">
      <div className="flex items-center gap-4 mb-6">
        <button onClick={() => navigate('home')} className="text-gray-400 hover:text-white">
          <ChevronLeft size={24} />
        </button>
        <h1 className="text-2xl font-bold">Profile</h1>
      </div>

      <div className="text-center mb-6">
        <div className="relative inline-block mb-4">
          <div className="w-24 h-24 rounded-full overflow-hidden mx-auto bg-gradient-to-br from-yellow-500 to-orange-600 p-[3px]">
            <div className="w-full h-full rounded-full bg-black overflow-hidden">
              <img src={getHeroImage(user?.avatarId)} alt="Avatar" className="w-full h-full object-cover" />
            </div>
          </div>
          <button 
            onClick={() => setShowAvatarModal(true)}
            className="absolute bottom-0 right-0 bg-yellow-500 text-black p-2 rounded-full hover:bg-yellow-400"
          >
            <Edit3 size={16} />
          </button>
        </div>
        <h2 className="text-2xl font-bold mb-1">{user?.username || `Agent ${user?.playerId.slice(0, 6)}`}</h2>
        <p className="text-gray-400 text-sm mb-2">{user?.playerId}</p>
        {user?.isVerified ? (
          <span className="inline-flex items-center gap-1 text-green-400 text-sm bg-green-900/20 px-3 py-1 rounded-full">
            <CheckCircle size={14} />
            Verified
          </span>
        ) : (
          <button 
            onClick={() => setShowVerifyModal(true)}
            className="inline-flex items-center gap-1 text-yellow-400 text-sm bg-yellow-900/20 px-3 py-1 rounded-full hover:bg-yellow-900/30"
          >
            <AlertCircle size={14} />
            Verify Account
          </button>
        )}
      </div>

      <div className="space-y-2 mb-6">
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between items-center">
          <span className="text-gray-400">Username</span>
          <button onClick={() => setShowUsernameModal(true)} className="text-yellow-500 hover:text-yellow-400">
            {user?.username || 'Set Username'}
          </button>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span className="text-gray-400">Wins</span>
          <span className="font-bold text-green-500">{user?.wins || 0}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span className="text-gray-400">Losses</span>
          <span className="font-bold text-red-500">{user?.losses || 0}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span className="text-gray-400">XP</span>
          <span className="font-bold text-yellow-500">{user?.xp || 0}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span className="text-gray-400">Total Games</span>
          <span className="font-bold">{user?.totalGames || 0}</span>
        </div>
      </div>

      <button
        onClick={logout}
        className="w-full bg-red-600 py-3 rounded-xl font-bold hover:bg-red-500 transition-colors flex items-center justify-center gap-2"
      >
        <LogOut size={20} />
        Logout
      </button>

      {showUsernameModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Set Username</h3>
            <input
              type="text"
              placeholder="Enter username"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4 text-white"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowUsernameModal(false)} className="flex-1 bg-gray-700 py-3 rounded-xl">
                Cancel
              </button>
              <button onClick={handleUpdateUsername} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold">
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {showAvatarModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 overflow-y-auto">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Choose Avatar</h3>
            <div className="grid grid-cols-4 gap-3 mb-4 max-h-96 overflow-y-auto">
              {HEROES.map((hero) => (
                <button
                  key={hero.id}
                  onClick={() => {
                    updateAvatar(hero.id);
                    setShowAvatarModal(false);
                  }}
                  className={`rounded-full overflow-hidden border-2 ${user?.avatarId === hero.id ? 'border-yellow-500' : 'border-transparent'} hover:border-yellow-500/50 transition-colors`}
                >
                  <img src={hero.url} alt={hero.name} className="w-full h-full object-cover" />
                </button>
              ))}
            </div>
            <button onClick={() => setShowAvatarModal(false)} className="w-full bg-gray-700 py-3 rounded-xl">
              Close
            </button>
          </div>
        </div>
      )}

      {showVerifyModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Verify Account</h3>
            <p className="text-sm text-gray-400 mb-4">Enter transaction ID of 0.001 ZEC deposit to verify</p>
            <input
              type="text"
              placeholder="Transaction ID"
              value={txId}
              onChange={(e) => setTxId(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4 text-white"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowVerifyModal(false)} className="flex-1 bg-gray-700 py-3 rounded-xl">
                Cancel
              </button>
              <button onClick={handleVerify} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold">
                Verify
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== BOTTOM NAV ====================
const BottomNav = () => {
  const { currentPage, navigate } = useStore();

  const navItems = [
    { page: 'home', icon: Home, label: 'Home' },
    { page: 'games', icon: Gamepad2, label: 'Games' },
    { page: 'wallet', icon: WalletIcon, label: 'Wallet' },
    { page: 'profile', icon: User, label: 'Profile' },
  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 bg-gray-900 border-t border-gray-800 px-6 py-4 z-40">
      <div className="flex justify-around max-w-md mx-auto">
        {navItems.map((item) => (
          <button
            key={item.page}
            onClick={() => navigate(item.page)}
            className={`flex flex-col items-center gap-1 transition-colors ${
              currentPage === item.page ? 'text-yellow-500' : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <item.icon size={24} />
            <span className="text-xs font-medium">{item.label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
};

// ==================== MAIN APP ====================
const App = () => {
  const { currentPage } = useStore();

  const renderPage = () => {
    switch (currentPage) {
      case 'landing': return <Landing />;
      case 'auth': return <Auth />;
      case 'home': return <HomePage />;
      case 'games': return <GamesPage />;
      case 'wallet': return <WalletPage />;
      case 'profile': return <ProfilePage />;
      default: return <Landing />;
    }
  };

  const showBottomNav = !['landing', 'auth'].includes(currentPage);

  return (
    <StoreProvider>
      <div className="min-h-screen bg-black text-white">
        {renderPage()}
        {showBottomNav && <BottomNav />}
      </div>
    </StoreProvider>
  );
};

export default App;