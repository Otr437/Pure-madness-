
import React, { createContext, useContext, useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { Home, Gamepad2, Wallet, User, Trophy, Calendar } from 'lucide-react';

// ==================== TYPES ====================
interface User {
  playerId: string;
  username: string | null;
  email: string | null;
  avatarId: string;
  balance: number;
  isVerified: boolean;
  hideBalance: boolean;
  wins: number;
  losses: number;
  xp: number;
  level?: number;
  totalGames: number;
  streak: number;
}

interface Transaction {
  id: string;
  type: string;
  amount: number;
  txId: string;
  status: string;
  createdAt: string;
}

interface Room {
  id: string;
  hostId: string;
  hostName: string;
  hostAvatar: string;
  type: 'PICTURE_RUSH' | 'PICTURE_MATCH';
  stake: number;
  maxPlayers: number;
  currentPlayers: number;
  status: string;
  playerIds: string[];
}

interface Game {
  gameId: string;
  type: 'PICTURE_RUSH' | 'PICTURE_MATCH';
  stake: number;
  players: any[];
  status: string;
}

// ==================== API CONFIG ====================
const API_URL = 'http://localhost:3001/api';

const api = {
  async request(endpoint: string, options: any = {}) {
    const token = localStorage.getItem('token');
    const headers: any = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Request failed');
    return data;
  },

  auth: {
    signup: (password: string, email?: string, username?: string) =>
      api.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ password, email, username }),
      }),
    login: (playerId: string, password: string) =>
      api.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ playerId, password }),
      }),
    verifyToken: (token: string) =>
      api.request('/auth/verify-token', {
        method: 'POST',
        body: JSON.stringify({ token }),
      }),
  },

  account: {
    getMe: () => api.request('/account/me'),
    verify: (txId: string) =>
      api.request('/account/verify', {
        method: 'POST',
        body: JSON.stringify({ txId }),
      }),
    updateUsername: (username: string) =>
      api.request('/account/username', {
        method: 'POST',
        body: JSON.stringify({ username }),
      }),
    updateAvatar: (avatarId: string) =>
      api.request('/account/avatar', {
        method: 'POST',
        body: JSON.stringify({ avatarId }),
      }),
  },

  wallet: {
    getBalance: () => api.request('/wallet/balance'),
    getAddress: () => api.request('/wallet/address'),
    deposit: (txId: string) =>
      api.request('/wallet/deposit', {
        method: 'POST',
        body: JSON.stringify({ txId }),
      }),
    withdraw: (amount: number, address: string) =>
      api.request('/wallet/withdraw', {
        method: 'POST',
        body: JSON.stringify({ amount, address }),
      }),
    getTransactions: () => api.request('/wallet/transactions'),
  },

  rooms: {
    list: (type?: string) => api.request(`/rooms${type ? `?type=${type}` : ''}`),
    create: (type: string, stake: number, maxPlayers: number) =>
      api.request('/rooms/create', {
        method: 'POST',
        body: JSON.stringify({ type, stake, maxPlayers }),
      }),
    join: (roomId: string) =>
      api.request('/rooms/join', {
        method: 'POST',
        body: JSON.stringify({ roomId }),
      }),
  },

  leaderboard: () => api.request('/leaderboard'),
};

// ==================== CONTEXT ====================
interface StoreContextType {
  user: User | null;
  token: string | null;
  transactions: Transaction[];
  rooms: Room[];
  activeGame: Game | null;
  login: (playerId: string, password: string) => Promise<boolean>;
  signup: (password: string) => Promise<boolean>;
  logout: () => void;
  verifyAccount: (txId: string) => Promise<boolean>;
  updateUsername: (username: string) => Promise<boolean>;
  updateAvatar: (avatarId: string) => Promise<void>;
  deposit: (txId: string) => Promise<boolean>;
  withdraw: (amount: number, address: string) => Promise<boolean>;
  createGame: (type: string, stake: number, maxPlayers: number) => Promise<void>;
  joinGame: (roomId: string) => Promise<void>;
  fetchRooms: () => Promise<void>;
  toggleHideBalance: () => Promise<void>;
}

const StoreContext = createContext<StoreContextType | null>(null);

export const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) throw new Error('useStore must be used within StoreProvider');
  return context;
};

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [rooms, setRooms] = useState<Room[]>([]);
  const [activeGame, setActiveGame] = useState<Game | null>(null);

  useEffect(() => {
    if (token) {
      api.auth.verifyToken(token).then((data) => {
        if (data.valid) {
          setUser(data.user);
          fetchUserData();
        } else {
          logout();
        }
      }).catch(() => logout());
    }
  }, [token]);

  const fetchUserData = async () => {
    try {
      const [meData, txData] = await Promise.all([
        api.account.getMe(),
        api.wallet.getTransactions(),
      ]);
      setUser(meData.user);
      setTransactions(txData.transactions || []);
    } catch (error) {
      console.error('Failed to fetch user data:', error);
    }
  };

  const login = async (playerId: string, password: string) => {
    try {
      const data = await api.auth.login(playerId, password);
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('token', data.token);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const signup = async (password: string) => {
    try {
      const data = await api.auth.signup(password);
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('token', data.token);
      return true;
    } catch (error) {
      console.error('Signup failed:', error);
      return false;
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  const verifyAccount = async (txId: string) => {
    try {
      await api.account.verify(txId);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Verification failed:', error);
      return false;
    }
  };

  const updateUsername = async (username: string) => {
    try {
      await api.account.updateUsername(username);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Update username failed:', error);
      return false;
    }
  };

  const updateAvatar = async (avatarId: string) => {
    try {
      await api.account.updateAvatar(avatarId);
      await fetchUserData();
    } catch (error) {
      console.error('Update avatar failed:', error);
    }
  };

  const deposit = async (txId: string) => {
    try {
      await api.wallet.deposit(txId);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Deposit failed:', error);
      return false;
    }
  };

  const withdraw = async (amount: number, address: string) => {
    try {
      await api.wallet.withdraw(amount, address);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Withdraw failed:', error);
      return false;
    }
  };

  const createGame = async (type: string, stake: number, maxPlayers: number) => {
    try {
      const data = await api.rooms.create(type, stake, maxPlayers);
      setActiveGame({ gameId: data.roomId, type, stake, players: [], status: 'WAITING' } as any);
    } catch (error) {
      console.error('Create game failed:', error);
    }
  };

  const joinGame = async (roomId: string) => {
    try {
      await api.rooms.join(roomId);
      const room = rooms.find(r => r.id === roomId);
      if (room) {
        setActiveGame({ gameId: room.id, type: room.type, stake: room.stake, players: [], status: 'WAITING' } as any);
      }
    } catch (error) {
      console.error('Join game failed:', error);
    }
  };

  const fetchRooms = async () => {
    try {
      const data = await api.rooms.list();
      setRooms(data.rooms || []);
    } catch (error) {
      console.error('Fetch rooms failed:', error);
    }
  };

  const toggleHideBalance = async () => {
    try {
      await api.request('/account/toggle-balance', { method: 'POST' });
      await fetchUserData();
    } catch (error) {
      console.error('Toggle hide balance failed:', error);
    }
  };

  return (
    <StoreContext.Provider
      value={{
        user,
        token,
        transactions,
        rooms,
        activeGame,
        login,
        signup,
        logout,
        verifyAccount,
        updateUsername,
        updateAvatar,
        deposit,
        withdraw,
        createGame,
        joinGame,
        fetchRooms,
        toggleHideBalance,
      }}
    >
      {children}
    </StoreContext.Provider>
  );
};

// ==================== COMPONENTS ====================

const Landing = () => {
  const navigate = useNavigate();
  const { user } = useStore();

  useEffect(() => {
    if (user) navigate('/');
  }, [user]);

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-b from-gray-900 to-black">
      <div className="text-center max-w-md">
        <h1 className="text-6xl font-black mb-4 bg-gradient-to-r from-yellow-400 to-orange-500 text-transparent bg-clip-text">
          ZEC ARENA
        </h1>
        <p className="text-gray-400 mb-8">Privacy-First PvP Gaming</p>
        <button
          onClick={() => navigate('/auth')}
          className="w-full bg-yellow-500 text-black font-bold py-4 rounded-xl hover:bg-yellow-400 transition"
        >
          PLAY ANONYMOUSLY
        </button>
      </div>
    </div>
  );
};

const Auth = () => {
  const [isLogin, setIsLogin] = useState(false);
  const [playerId, setPlayerId] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, signup } = useStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const success = isLogin ? await login(playerId, password) : await signup(password);
    setLoading(false);
    if (success) navigate('/');
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-b from-gray-900 to-black">
      <div className="w-full max-w-md bg-gray-800 p-8 rounded-2xl">
        <div className="flex gap-4 mb-6">
          <button onClick={() => setIsLogin(false)} className={`flex-1 pb-2 ${!isLogin ? 'border-b-2 border-yellow-500' : ''}`}>
            SIGN UP
          </button>
          <button onClick={() => setIsLogin(true)} className={`flex-1 pb-2 ${isLogin ? 'border-b-2 border-yellow-500' : ''}`}>
            LOGIN
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          {isLogin && (
            <input
              type="text"
              placeholder="Player ID or Username"
              value={playerId}
              onChange={(e) => setPlayerId(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
            />
          )}
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
          />
          <button type="submit" disabled={loading} className="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl">
            {loading ? 'Loading...' : isLogin ? 'LOGIN' : 'CREATE ID'}
          </button>
        </form>
      </div>
    </div>
  );
};

const HomePage = () => {
  const { user } = useStore();
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Welcome, {user?.username || `Agent ${user?.playerId.slice(0, 6)}`}</h1>
      <div className="bg-gray-800 p-6 rounded-2xl">
        <h2 className="text-xl font-bold mb-2">PVP MODE</h2>
        <p className="text-gray-400 mb-4">Stake ZEC. Win Big.</p>
        <button className="bg-yellow-500 text-black font-bold px-6 py-2 rounded-xl">
          Play Now
        </button>
      </div>
    </div>
  );
};

const WalletPage = () => {
  const { user, transactions, deposit, withdraw, toggleHideBalance } = useStore();
  const [showDeposit, setShowDeposit] = useState(false);
  const [txId, setTxId] = useState('');

  const handleDeposit = async () => {
    await deposit(txId);
    setShowDeposit(false);
    setTxId('');
  };

  return (
    <div className="p-6 space-y-6">
      <div className="bg-gray-800 p-8 rounded-2xl text-center">
        <p className="text-gray-400 text-sm mb-2">Balance</p>
        <h2 className="text-4xl font-bold mb-2">
          {user?.hideBalance ? '****' : `${user?.balance.toFixed(4)} ZEC`}
        </h2>
        <button onClick={toggleHideBalance} className="text-sm text-gray-500">
          {user?.hideBalance ? 'Show' : 'Hide'}
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <button onClick={() => setShowDeposit(true)} className="bg-green-600 p-4 rounded-xl font-bold">
          Deposit
        </button>
        <button className="bg-red-600 p-4 rounded-xl font-bold">
          Withdraw
        </button>
      </div>

      {showDeposit && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Deposit ZEC</h3>
            <input
              type="text"
              placeholder="Transaction ID"
              value={txId}
              onChange={(e) => setTxId(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowDeposit(false)} className="flex-1 bg-gray-700 py-3 rounded-xl">
                Cancel
              </button>
              <button onClick={handleDeposit} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-2">
        <h3 className="font-bold">Transactions</h3>
        {transactions.map((tx) => (
          <div key={tx.id} className="bg-gray-800 p-4 rounded-xl flex justify-between">
            <div>
              <p className="font-bold">{tx.type}</p>
              <p className="text-sm text-gray-500">{new Date(tx.createdAt).toLocaleDateString()}</p>
            </div>
            <p className="font-bold">{tx.amount.toFixed(4)} ZEC</p>
          </div>
        ))}
      </div>
    </div>
  );
};

const ProfilePage = () => {
  const { user, logout } = useStore();
  const navigate = useNavigate();

  return (
    <div className="p-6 space-y-6">
      <div className="text-center">
        <div className="w-24 h-24 bg-yellow-500 rounded-full mx-auto mb-4"></div>
        <h2 className="text-2xl font-bold">{user?.username || `Agent ${user?.playerId}`}</h2>
        <p className="text-gray-400">{user?.playerId}</p>
        {user?.isVerified ? (
          <span className="text-green-400 text-sm">✓ Verified</span>
        ) : (
          <span className="text-red-400 text-sm">✗ Unverified</span>
        )}
      </div>

      <div className="space-y-2">
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>Wins</span>
          <span className="font-bold">{user?.wins}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>Losses</span>
          <span className="font-bold">{user?.losses}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>XP</span>
          <span className="font-bold">{user?.xp}</span>
        </div>
      </div>

      <button onClick={logout} className="w-full bg-red-600 py-3 rounded-xl font-bold">
        Logout
      </button>
    </div>
  );
};

const BottomNav = () => {
  const navigate = useNavigate();
  const location = window.location.pathname;

  const navItems = [
    { path: '/', icon: Home, label: 'Home' },
    { path: '/games', icon: Gamepad2, label: 'Games' },
    { path: '/wallet', icon: Wallet, label: 'Wallet' },
    { path: '/profile', icon: User, label: 'Profile' },
  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 bg-gray-900 border-t border-gray-800 px-6 py-4">
      <div className="flex justify-around">
        {navItems.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={`flex flex-col items-center gap-1 ${
              location === item.path ? 'text-yellow-500' : 'text-gray-500'
            }`}
          >
            <item.icon size={24} />
            <span className="text-xs">{item.label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
};

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user } = useStore();
  return user ? <>{children}</> : <Navigate to="/landing" />;
};

// ==================== MAIN APP ====================
const App = () => {
  return (
    <StoreProvider>
      <Router>
        <div className="min-h-screen bg-black text-white pb-20">
          <Routes>
            <Route path="/landing" element={<Landing />} />
            <Route path="/auth" element={<Auth />} />
            <Route path="/" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
            <Route path="/games" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
            <Route path="/wallet" element={<ProtectedRoute><WalletPage /></ProtectedRoute>} />
            <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
          </Routes>
          {window.location.pathname !== '/landing' && window.location.pathname !== '/auth' && <BottomNav />}
        </div>
      </Router>
    </StoreProvider>
  );
};

export default App;