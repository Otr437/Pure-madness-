// components/WalletBalances.tsx
import React, { useState, useEffect, useCallback } from 'react';
import { Eye, EyeOff, RefreshCw, Wallet, CheckCircle, XCircle, AlertCircle, ExternalLink, LogOut, Network, Copy, Activity } from 'lucide-react';
import { api } from '../lib/api';

interface WalletConnection {
  address: string;
  chainId?: string;
  balance?: string;
  connected: boolean;
  provider: string;
  shieldedAddress?: string;
  transparentAddress?: string;
}

interface ConnectedWallets {
  evm: WalletConnection | null;
  starknet: WalletConnection | null;
  zcash: WalletConnection | null;
  monero: WalletConnection | null;
}

export default function WalletBalances() {
  const [balances, setBalances] = useState<any>(null);
  const [showBalances, setShowBalances] = useState(true);
  const [loading, setLoading] = useState(true);
  const [connectedWallets, setConnectedWallets] = useState<ConnectedWallets>({
    evm: null,
    starknet: null,
    zcash: null,
    monero: null
  });
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [currentNetwork, setCurrentNetwork] = useState<string>('');
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [pendingTx, setPendingTx] = useState<string>('');

  useEffect(() => {
    loadBalances();
    setupWalletListeners();
    checkExistingConnections();
    setupReconnectionHandling();
    
    return () => {
      cleanupListeners();
    };
  }, []);

  const setupReconnectionHandling = () => {
    window.addEventListener('online', handleNetworkReconnect);
    window.addEventListener('focus', checkConnectionStatus);
    window.addEventListener('visibilitychange', handleVisibilityChange);
  };

  const handleVisibilityChange = () => {
    if (!document.hidden) {
      checkConnectionStatus();
    }
  };

  const handleNetworkReconnect = async () => {
    console.log('Network reconnected, checking wallet connections...');
    setIsReconnecting(true);
    await checkConnectionStatus();
    setIsReconnecting(false);
  };

  const checkConnectionStatus = async () => {
    if (connectedWallets.evm && typeof window.ethereum !== 'undefined') {
      try {
        const accounts = await window.ethereum.request({ method: 'eth_accounts' });
        if (accounts.length === 0) {
          setConnectedWallets(prev => ({ ...prev, evm: null }));
          setError('EVM wallet disconnected');
        }
      } catch (error) {
        console.error('Failed to check EVM connection:', error);
      }
    }

    if (connectedWallets.starknet) {
      const argentX = window.starknet_argentX;
      const braavos = window.starknet_braavos;
      
      if (argentX && !argentX.isConnected && braavos && !braavos.isConnected) {
        setConnectedWallets(prev => ({ ...prev, starknet: null }));
        setError('StarkNet wallet disconnected');
      }
    }
  };

  const setupWalletListeners = () => {
    if (typeof window.ethereum !== 'undefined') {
      window.ethereum.on('accountsChanged', handleEVMAccountsChanged);
      window.ethereum.on('chainChanged', handleEVMChainChanged);
      window.ethereum.on('disconnect', handleEVMDisconnect);
      window.ethereum.on('connect', handleEVMConnect);
      window.ethereum.on('message', handleEVMMessage);
    }
    
    if (typeof window.starknet_argentX !== 'undefined') {
      window.starknet_argentX.on('accountsChanged', handleStarknetAccountsChanged);
      window.starknet_argentX.on('networkChanged', handleStarknetNetworkChanged);
    }
    
    if (typeof window.starknet_braavos !== 'undefined') {
      window.starknet_braavos.on('accountsChanged', handleStarknetAccountsChanged);
      window.starknet_braavos.on('networkChanged', handleStarknetNetworkChanged);
    }
  };

  const cleanupListeners = () => {
    if (window.ethereum) {
      window.ethereum.removeListener('accountsChanged', handleEVMAccountsChanged);
      window.ethereum.removeListener('chainChanged', handleEVMChainChanged);
      window.ethereum.removeListener('disconnect', handleEVMDisconnect);
      window.ethereum.removeListener('connect', handleEVMConnect);
      window.ethereum.removeListener('message', handleEVMMessage);
    }
    
    window.removeEventListener('online', handleNetworkReconnect);
    window.removeEventListener('focus', checkConnectionStatus);
    window.removeEventListener('visibilitychange', handleVisibilityChange);
  };

  const handleEVMMessage = (message: any) => {
    console.log('EVM message received:', message);
  };

  const handleEVMConnect = (connectInfo: any) => {
    console.log('EVM wallet connected:', connectInfo);
    setCurrentNetwork(connectInfo.chainId);
    setSuccess('Wallet connected successfully');
    setTimeout(() => setSuccess(''), 3000);
  };

  const handleEVMDisconnect = (error: any) => {
    console.log('EVM wallet disconnected:', error);
    setConnectedWallets(prev => ({ ...prev, evm: null }));
    setError('Wallet disconnected. Please reconnect.');
    setTimeout(() => setError(''), 5000);
  };

  const handleEVMAccountsChanged = (accounts: string[]) => {
    if (accounts.length === 0) {
      setConnectedWallets(prev => ({ ...prev, evm: null }));
      setError('Account disconnected');
      setTimeout(() => setError(''), 5000);
    } else {
      connectEVMWallet();
    }
  };

  const handleEVMChainChanged = (chainId: string) => {
    console.log('Chain changed to:', chainId);
    setCurrentNetwork(chainId);
    setSuccess(`Switched to ${getNetworkName(chainId)}`);
    setTimeout(() => setSuccess(''), 3000);
    window.location.reload();
  };

  const handleStarknetAccountsChanged = () => {
    const argentX = window.starknet_argentX;
    const braavos = window.starknet_braavos;
    
    if ((argentX && argentX.isConnected) || (braavos && braavos.isConnected)) {
      connectStarknetWallet();
    } else {
      setConnectedWallets(prev => ({ ...prev, starknet: null }));
      setError('StarkNet account changed');
      setTimeout(() => setError(''), 5000);
    }
  };

  const handleStarknetNetworkChanged = (networkId: string) => {
    console.log('StarkNet network changed to:', networkId);
    setSuccess('StarkNet network changed');
    setTimeout(() => setSuccess(''), 3000);
    loadBalances();
  };

  const checkExistingConnections = async () => {
    if (typeof window.ethereum !== 'undefined') {
      try {
        const accounts = await window.ethereum.request({ method: 'eth_accounts' });
        if (accounts.length > 0) {
          await connectEVMWallet();
        }
      } catch (e) {
        console.error('Failed to check existing EVM connection:', e);
      }
    }
    
    if (typeof window.starknet_argentX !== 'undefined' && window.starknet_argentX.isConnected) {
      await connectArgentX();
    }
    
    if (typeof window.starknet_braavos !== 'undefined' && window.starknet_braavos.isConnected) {
      await connectBraavos();
    }
  };

  const loadBalances = async () => {
    try {
      const data = await api.getBalances();
      setBalances(data);
    } catch (err) {
      console.error('Failed to load balances:', err);
      setError('Failed to load balances from API');
    } finally {
      setLoading(false);
    }
  };

  const connectEVMWallet = async () => {
    setError('');
    if (typeof window.ethereum === 'undefined') {
      setError('MetaMask or compatible EVM wallet not installed. Please install MetaMask, Coinbase Wallet, or Trust Wallet.');
      window.open('https://metamask.io/download/', '_blank');
      return;
    }

    try {
      const accounts = await window.ethereum.request({ 
        method: 'eth_requestAccounts' 
      });
      
      if (!accounts || accounts.length === 0) {
        throw new Error('No accounts returned from wallet');
      }
      
      const chainId = await window.ethereum.request({ 
        method: 'eth_chainId' 
      });

      const balance = await window.ethereum.request({
        method: 'eth_getBalance',
        params: [accounts[0], 'latest']
      });

      const balanceInEth = (parseInt(balance, 16) / 1e18).toFixed(6);
      
      const providerName = window.ethereum.isMetaMask ? 'MetaMask' :
                          window.ethereum.isCoinbaseWallet ? 'Coinbase Wallet' :
                          window.ethereum.isTrust ? 'Trust Wallet' : 
                          window.ethereum.isBraveWallet ? 'Brave Wallet' :
                          'EVM Wallet';

      setConnectedWallets(prev => ({
        ...prev,
        evm: {
          address: accounts[0],
          chainId: chainId,
          balance: balanceInEth,
          connected: true,
          provider: providerName
        }
      }));
      
      setCurrentNetwork(chainId);
      setSuccess(`Connected to ${providerName}`);
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      if (err.code === 4001) {
        setError('Connection request rejected by user');
      } else if (err.code === -32002) {
        setError('Connection request already pending. Please check your wallet extension.');
      } else if (err.code === -32603) {
        setError('Internal wallet error. Please try again.');
      } else {
        setError(`EVM wallet connection failed: ${err.message}`);
      }
      console.error('EVM connection failed:', err);
    }
  };

  const disconnectEVMWallet = async () => {
    try {
      if (window.ethereum && typeof window.ethereum.close === 'function') {
        await window.ethereum.close();
      }
      
      setConnectedWallets(prev => ({ ...prev, evm: null }));
      setCurrentNetwork('');
      setSuccess('EVM wallet disconnected');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      console.error('Disconnect failed:', err);
      setConnectedWallets(prev => ({ ...prev, evm: null }));
      setError('Failed to disconnect properly, but wallet has been removed');
      setTimeout(() => setError(''), 5000);
    }
  };

  const switchEVMNetwork = async (chainId: string) => {
    if (!window.ethereum) {
      setError('No EVM wallet connected');
      return;
    }
    
    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId }]
      });
      setSuccess(`Switched to ${getNetworkName(chainId)}`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      if (err.code === 4902) {
        setError('This network has not been added to your wallet. Add it first.');
        setTimeout(() => setError(''), 5000);
      } else if (err.code === 4001) {
        setError('Network switch rejected by user');
        setTimeout(() => setError(''), 5000);
      } else {
        setError(`Failed to switch network: ${err.message}`);
        setTimeout(() => setError(''), 5000);
      }
    }
  };

  const addEVMNetwork = async (networkConfig: any) => {
    if (!window.ethereum) {
      setError('No EVM wallet connected');
      return;
    }
    
    try {
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [networkConfig]
      });
      setSuccess('Network added successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      if (err.code === 4001) {
        setError('Network addition rejected by user');
      } else {
        setError(`Failed to add network: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
    }
  };

  const signEVMMessage = async (message: string) => {
    if (!connectedWallets.evm || !window.ethereum) {
      setError('Please connect an EVM wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, connectedWallets.evm.address]
      });
      setSuccess('Message signed successfully');
      setTimeout(() => setSuccess(''), 3000);
      return signature;
    } catch (err: any) {
      if (err.code === 4001) {
        setError('Signing request rejected by user');
      } else {
        setError(`Signing failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Signing error:', err);
      return null;
    }
  };

  const signEVMTypedData = async (typedData: any) => {
    if (!connectedWallets.evm || !window.ethereum) {
      setError('Please connect an EVM wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      const signature = await window.ethereum.request({
        method: 'eth_signTypedData_v4',
        params: [connectedWallets.evm.address, JSON.stringify(typedData)]
      });
      setSuccess('Typed data signed successfully');
      setTimeout(() => setSuccess(''), 3000);
      return signature;
    } catch (err: any) {
      if (err.code === 4001) {
        setError('Signing request rejected by user');
      } else {
        setError(`Typed data signing failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      return null;
    }
  };

  const sendEVMTransaction = async (tx: any) => {
    if (!connectedWallets.evm || !window.ethereum) {
      setError('Please connect an EVM wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Waiting for user confirmation...');
      const txHash = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{
          from: connectedWallets.evm.address,
          ...tx
        }]
      });
      setPendingTx(`Transaction sent: ${txHash}`);
      setSuccess('Transaction submitted successfully');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return txHash;
    } catch (err: any) {
      setPendingTx('');
      if (err.code === 4001) {
        setError('Transaction rejected by user');
      } else if (err.code === -32000) {
        setError('Insufficient funds for transaction + gas');
      } else if (err.code === -32603) {
        setError('Transaction failed. Check gas limits and balance.');
      } else {
        setError(`Transaction failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Transaction error:', err);
      return null;
    }
  };

  const getEVMTransactionReceipt = async (txHash: string) => {
    if (!window.ethereum) return null;
    
    try {
      const receipt = await window.ethereum.request({
        method: 'eth_getTransactionReceipt',
        params: [txHash]
      });
      return receipt;
    } catch (err: any) {
      console.error('Failed to get transaction receipt:', err);
      return null;
    }
  };

  const watchEVMAsset = async (tokenAddress: string, tokenSymbol: string, tokenDecimals: number, tokenImage?: string) => {
    if (!window.ethereum) {
      setError('No EVM wallet connected');
      return;
    }

    try {
      const wasAdded = await window.ethereum.request({
        method: 'wallet_watchAsset',
        params: {
          type: 'ERC20',
          options: {
            address: tokenAddress,
            symbol: tokenSymbol,
            decimals: tokenDecimals,
            image: tokenImage
          }
        }
      });

      if (wasAdded) {
        setSuccess(`${tokenSymbol} added to wallet`);
      } else {
        setError('Token not added to wallet');
      }
      setTimeout(() => {
        setSuccess('');
        setError('');
      }, 3000);
    } catch (err: any) {
      setError(`Failed to add token: ${err.message}`);
      setTimeout(() => setError(''), 5000);
    }
  };

  const connectArgentX = async () => {
    setError('');
    if (typeof window.starknet_argentX === 'undefined') {
      setError('Argent X wallet not installed');
      window.open('https://www.argent.xyz/argent-x/', '_blank');
      return;
    }

    try {
      const result = await window.starknet_argentX.enable({ starknetVersion: 'v5' });
      
      if (!window.starknet_argentX.isConnected) {
        throw new Error('Failed to connect to Argent X');
      }

      const address = window.starknet_argentX.selectedAddress;
      const chainId = window.starknet_argentX.chainId;

      setConnectedWallets(prev => ({
        ...prev,
        starknet: {
          address: address,
          chainId: chainId,
          connected: true,
          provider: 'Argent X'
        }
      }));

      setSuccess('Connected to Argent X');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      if (err.code === 'USER_REFUSED' || err.message?.includes('rejected')) {
        setError('Connection request rejected by user');
      } else {
        setError(`Argent X connection failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Argent X error:', err);
    }
  };

  const connectBraavos = async () => {
    setError('');
    if (typeof window.starknet_braavos === 'undefined') {
      setError('Braavos wallet not installed');
      window.open('https://braavos.app/', '_blank');
      return;
    }

    try {
      const result = await window.starknet_braavos.enable({ starknetVersion: 'v5' });
      
      if (!window.starknet_braavos.isConnected) {
        throw new Error('Failed to connect to Braavos');
      }

      const address = window.starknet_braavos.selectedAddress;
      const chainId = window.starknet_braavos.chainId;

      setConnectedWallets(prev => ({
        ...prev,
        starknet: {
          address: address,
          chainId: chainId,
          connected: true,
          provider: 'Braavos'
        }
      }));

      setSuccess('Connected to Braavos');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      if (err.code === 'USER_REFUSED' || err.message?.includes('rejected')) {
        setError('Connection request rejected by user');
      } else {
        setError(`Braavos connection failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Braavos error:', err);
    }
  };

  const disconnectStarknetWallet = async () => {
    const wallet = connectedWallets.starknet;
    if (!wallet) return;

    try {
      const provider = wallet.provider === 'Argent X' ? window.starknet_argentX : window.starknet_braavos;
      
      if (provider && typeof provider.disable === 'function') {
        await provider.disable();
      }
      
      setConnectedWallets(prev => ({ ...prev, starknet: null }));
      setSuccess('StarkNet wallet disconnected');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      console.error('StarkNet disconnect failed:', err);
      setConnectedWallets(prev => ({ ...prev, starknet: null }));
      setError('Failed to disconnect properly, but wallet has been removed');
      setTimeout(() => setError(''), 5000);
    }
  };

  const connectStarknetWallet = async () => {
    if (window.starknet_argentX?.isConnected) {
      await connectArgentX();
    } else if (window.starknet_braavos?.isConnected) {
      await connectBraavos();
    } else {
      setError('No StarkNet wallet is currently connected');
      setTimeout(() => setError(''), 5000);
    }
  };

  const signStarkNetTransaction = async (calls: any[]) => {
    const wallet = connectedWallets.starknet;
    if (!wallet) {
      setError('Please connect a StarkNet wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    const provider = wallet.provider === 'Argent X' ? window.starknet_argentX : window.starknet_braavos;
    
    if (!provider || !provider.account) {
      setError('StarkNet provider or account not available');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Waiting for StarkNet transaction confirmation...');
      const result = await provider.account.execute(calls);
      setPendingTx(`Transaction submitted: ${result.transaction_hash}`);
      setSuccess('StarkNet transaction submitted successfully');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return result.transaction_hash;
    } catch (err: any) {
      setPendingTx('');
      if (err.code === 'USER_REFUSED' || err.message?.includes('rejected')) {
        setError('Transaction rejected by user');
      } else {
        setError(`StarkNet transaction failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('StarkNet signing error:', err);
      return null;
    }
  };

  const signStarkNetMessage = async (message: any) => {
    const wallet = connectedWallets.starknet;
    if (!wallet) {
      setError('Please connect a StarkNet wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    const provider = wallet.provider === 'Argent X' ? window.starknet_argentX : window.starknet_braavos;
    
    if (!provider || !provider.account) {
      setError('StarkNet provider or account not available');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      const signature = await provider.account.signMessage(message);
      setSuccess('Message signed successfully');
      setTimeout(() => setSuccess(''), 3000);
      return signature;
    } catch (err: any) {
      if (err.code === 'USER_REFUSED' || err.message?.includes('rejected')) {
        setError('Signing request rejected by user');
      } else {
        setError(`Message signing failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      return null;
    }
  };

  const connectZashiWallet = () => {
    setError('');
    alert('Zashi Wallet (official Zcash wallet by Electric Coin Company) is available on iOS and Android. Download from App Store or Google Play Store. For desktop shielded transactions, use Brave Wallet which supports Zcash.');
    window.open('https://z.cash/ecosystem/zashi-wallet/', '_blank');
  };

  const connectYWallet = async () => {
    if (typeof window.ywallet === 'undefined') {
      setError('YWallet not detected. YWallet is available for desktop (Windows, macOS, Linux) and mobile.');
      window.open('https://ywallet.app', '_blank');
      return;
    }

    setError('');
    try {
      const connection = await window.ywallet.connect();
      
      if (!connection || (!connection.shieldedAddress && !connection.transparentAddress)) {
        throw new Error('Failed to get wallet addresses from YWallet');
      }
      
      setConnectedWallets(prev => ({
        ...prev,
        zcash: {
          address: connection.transparentAddress || connection.shieldedAddress,
          shieldedAddress: connection.shieldedAddress,
          transparentAddress: connection.transparentAddress,
          connected: true,
          provider: 'YWallet'
        }
      }));
      
      setSuccess('Connected to YWallet');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      setError(`YWallet connection failed: ${err.message}`);
      setTimeout(() => setError(''), 5000);
      console.error('YWallet error:', err);
    }
  };

  const disconnectZcashWallet = async () => {
    if (!connectedWallets.zcash) return;

    try {
      if (window.ywallet && typeof window.ywallet.disconnect === 'function') {
        await window.ywallet.disconnect();
      }
      
      setConnectedWallets(prev => ({ ...prev, zcash: null }));
      setSuccess('Zcash wallet disconnected');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      console.error('Zcash disconnect failed:', err);
      setConnectedWallets(prev => ({ ...prev, zcash: null }));
    }
  };

  const signZcashTransaction = async (transaction: any) => {
    if (!connectedWallets.zcash || !window.ywallet) {
      setError('Please connect a Zcash wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Waiting for Zcash transaction confirmation...');
      const signedTx = await window.ywallet.signTransaction(transaction);
      setPendingTx('Transaction signed successfully');
      setSuccess('Zcash transaction signed');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return signedTx;
    } catch (err: any) {
      setPendingTx('');
      if (err.message?.includes('rejected') || err.message?.includes('cancelled')) {
        setError('Transaction rejected by user');
      } else {
        setError(`Zcash transaction failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Zcash signing error:', err);
      return null;
    }
  };

  const sendZcashShieldedTransaction = async (toAddress: string, amount: string, memo?: string) => {
    if (!connectedWallets.zcash || !window.ywallet) {
      setError('Please connect a Zcash wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Creating shielded Zcash transaction...');
      const txData = {
        to: toAddress,
        amount: amount,
        memo: memo || '',
        shielded: true
      };
      
      const result = await window.ywallet.sendTransaction(txData);
      setPendingTx(`Shielded transaction sent: ${result.txid}`);
      setSuccess('Shielded Zcash transaction sent successfully');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return result.txid;
    } catch (err: any) {
      setPendingTx('');
      setError(`Shielded transaction failed: ${err.message}`);
      setTimeout(() => setError(''), 5000);
      return null;
    }
  };

  const connectCakeWallet = () => {
    setError('');
    alert('Cake Wallet and Monero.com (by the same team) support Monero (XMR) transactions on iOS and Android. These are the most popular mobile Monero wallets. Download from App Store or Google Play Store.');
    window.open('https://monero.com/', '_blank');
  };

  const connectMonerujo = () => {
    setError('');
    alert('Monerujo is an Android-only open-source Monero wallet. It supports full Monero functionality including subaddresses and local nodes. Download from Google Play Store or F-Droid.');
    window.open('https://monerujo.io/', '_blank');
  };

  const connectMoneroWallet = async () => {
    if (typeof window.monero === 'undefined') {
      setError('Monero wallet RPC interface not detected. Please install Monero GUI or CLI wallet and enable RPC access.');
      window.open('https://getmonero.org/downloads/', '_blank');
      return;
    }

    setError('');
    try {
      const connection = await window.monero.connect();
      
      if (!connection || !connection.address) {
        throw new Error('Failed to get Monero wallet address');
      }
      
      setConnectedWallets(prev => ({
        ...prev,
        monero: {
          address: connection.address,
          connected: true,
          provider: 'Monero Wallet RPC'
        }
      }));
      
      setSuccess('Connected to Monero wallet');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      setError(`Monero wallet connection failed: ${err.message}`);
      setTimeout(() => setError(''), 5000);
      console.error('Monero error:', err);
    }
  };

  const disconnectMoneroWallet = async () => {
    if (!connectedWallets.monero) return;

    try {
      if (window.monero && typeof window.monero.disconnect === 'function') {
        await window.monero.disconnect();
      }
      
      setConnectedWallets(prev => ({ ...prev, monero: null }));
      setSuccess('Monero wallet disconnected');
      setTimeout(() => setSuccess(''), 3000);
      await loadBalances();
    } catch (err: any) {
      console.error('Monero disconnect failed:', err);
      setConnectedWallets(prev => ({ ...prev, monero: null }));
    }
  };

  const signMoneroTransaction = async (transaction: any) => {
    if (!connectedWallets.monero || !window.monero) {
      setError('Please connect a Monero wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Waiting for Monero transaction confirmation...');
      const signedTx = await window.monero.signTransaction(transaction);
      setPendingTx('Transaction signed successfully');
      setSuccess('Monero transaction signed');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return signedTx;
    } catch (err: any) {
      setPendingTx('');
      if (err.message?.includes('rejected') || err.message?.includes('cancelled')) {
        setError('Transaction rejected by user');
      } else {
        setError(`Monero transaction failed: ${err.message}`);
      }
      setTimeout(() => setError(''), 5000);
      console.error('Monero signing error:', err);
      return null;
    }
  };

  const sendMoneroTransaction = async (toAddress: string, amount: string, paymentId?: string) => {
    if (!connectedWallets.monero || !window.monero) {
      setError('Please connect a Monero wallet first');
      setTimeout(() => setError(''), 5000);
      return null;
    }

    try {
      setPendingTx('Creating Monero transaction...');
      const txData = {
        destinations: [{
          address: toAddress,
          amount: amount
        }],
        payment_id: paymentId || '',
        priority: 1
      };
      
      const result = await window.monero.transfer(txData);
      setPendingTx(`Monero transaction sent: ${result.tx_hash}`);
      setSuccess('Monero transaction sent successfully');
      setTimeout(() => {
        setPendingTx('');
        setSuccess('');
      }, 5000);
      return result.tx_hash;
    } catch (err: any) {
      setPendingTx('');
      setError(`Monero transaction failed: ${err.message}`);
      setTimeout(() => setError(''), 5000);
      return null;
    }
  };

  const formatBalance = (balance: number, currency: string) => {
    if (!showBalances) return '••••••';
    return new Intl.NumberFormat('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: currency === 'XMR' ? 12 : 6
    }).format(balance);
  };

  const formatAddress = (address: string, startChars: number = 6, endChars: number = 4) => {
    if (!address) return 'Not connected';
    if (address.length <= startChars + endChars) return address;
    return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
  };

  const copyToClipboard = async (text: string, label: string = 'Text') => {
    try {
      await navigator.clipboard.writeText(text);
      setSuccess(`${label} copied to clipboard`);
      setTimeout(() => setSuccess(''), 2000);
    } catch (err) {
      setError('Failed to copy to clipboard');
      setTimeout(() => setError(''), 3000);
    }
  };

  const getNetworkName = (chainId: string) => {
    const networks: Record<string, string> = {
      '0x1': 'Ethereum Mainnet',
      '0x89': 'Polygon',
      '0xa4b1': 'Arbitrum One',
      '0xa': 'Optimism',
      '0x38': 'BNB Chain',
      '0xa86a': 'Avalanche C-Chain',
      '0x2105': 'Base',
      '0x64': 'Gnosis Chain',
      '0xa4ec': 'Celo',
      '0x504': 'Moonbeam',
      '0x505': 'Moonriver'
    };
    return networks[chainId] || `Chain ${chainId}`;
  };

  const getNetworkExplorer = (chainId: string) => {
    const explorers: Record<string, string> = {
      '0x1': 'https://etherscan.io',
      '0x89': 'https://polygonscan.com',
      '0xa4b1': 'https://arbiscan.io',
      '0xa': 'https://optimistic.etherscan.io',
      '0x38': 'https://bscscan.com',
      '0xa86a': 'https://snowtrace.io'
    };
    return explorers[chainId] || 'https://etherscan.io';
  };

  const openInExplorer = (address: string, type: 'address' | 'tx' = 'address') => {
    if (!connectedWallets.evm?.chainId) return;
    const explorer = getNetworkExplorer(connectedWallets.evm.chainId);
    const url = `${explorer}/${type}/${address}`;
    window.open(url, '_blank');
  };

  if (loading) {
    return (
      <div className="bg-gray-800 rounded-xl p-8 border border-gray-700">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <span className="ml-3 text-gray-400">Loading wallet balances...</span>
        </div>
      </div>
    );
  }

  if (!balances) {
    return (
      <div className="bg-gray-800 rounded-xl p-8 border border-gray-700">
        <div className="flex items-center justify-center py-8">
          <AlertCircle className="h-8 w-8 text-red-500 mr-3" />
          <div>
            <p className="text-lg font-semibold text-red-400">Failed to Load Balances</p>
            <button 
              onClick={loadBalances}
              className="mt-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-xl p-8 border border-gray-700">
      {error && (
        <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0" />
            <span className="text-red-200 text-sm">{error}</span>
          </div>
          <button onClick={() => setError('')} className="ml-2 flex-shrink-0">
            <XCircle className="h-4 w-4 text-red-400 hover:text-red-300" />
          </button>
        </div>
      )}

      {success && (
        <div className="mb-4 p-3 bg-green-900/50 border border-green-700 rounded-lg flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
            <span className="text-green-200 text-sm">{success}</span>
          </div>
          <button onClick={() => setSuccess('')} className="ml-2 flex-shrink-0">
            <XCircle className="h-4 w-4 text-green-400 hover:text-green-300" />
          </button>
        </div>
      )}

      {pendingTx && (
        <div className="mb-4 p-3 bg-blue-900/50 border border-blue-700 rounded-lg flex items-center space-x-2">
          <Activity className="h-5 w-5 text-blue-400 animate-pulse flex-shrink-0" />
          <span className="text-blue-200 text-sm">{pendingTx}</span>
        </div>
      )}

      {isReconnecting && (
        <div className="mb-4 p-3 bg-yellow-900/50 border border-yellow-700 rounded-lg flex items-center space-x-2">
          <RefreshCw className="h-5 w-5 text-yellow-400 animate-spin flex-shrink-0" />
          <span className="text-yellow-200 text-sm">Reconnecting wallets...</span>
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">Wallet Balances</h2>
          {currentNetwork && connectedWallets.evm && (
            <div className="flex items-center space-x-2 mt-1">
              <Network className="h-4 w-4 text-gray-400" />
              <span className="text-sm text-gray-400">{getNetworkName(currentNetwork)}</span>
              <button
                onClick={() => openInExplorer(connectedWallets.evm!.address, 'address')}
                className="text-blue-400 hover:text-blue-300"
              >
                <ExternalLink className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowBalances(!showBalances)}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
            title={showBalances ? 'Hide balances' : 'Show balances'}
          >
            {showBalances ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
          </button>
          <button
            onClick={loadBalances}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
            title="Refresh balances"
            disabled={loading}
          >
            <RefreshCw className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {(connectedWallets.evm || connectedWallets.starknet || connectedWallets.zcash || connectedWallets.monero) && (
        <div className="mb-6 p-4 bg-gray-900 rounded-lg border border-gray-700">
          <h3 className="text-sm font-semibold mb-3 text-gray-300 flex items-center">
            <CheckCircle className="h-4 w-4 mr-2 text-green-500" />
            Connected Wallets
          </h3>
          <div className="space-y-2">
            {connectedWallets.evm && (
              <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg hover:bg-gray-750 transition-colors">
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-semibold">{connectedWallets.evm.provider}</span>
                      <span className="text-xs px-2 py-0.5 bg-blue-900 text-blue-300 rounded">EVM</span>
                    </div>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-xs text-gray-400 font-mono truncate">{formatAddress(connectedWallets.evm.address, 8, 6)}</span>
                      <button
                        onClick={() => copyToClipboard(connectedWallets.evm!.address, 'Address')}
                        className="p-1 hover:bg-gray-700 rounded transition-colors"
                        title="Copy address"
                      >
                        <Copy className="h-3 w-3 text-gray-400" />
                      </button>
                    </div>
                    {connectedWallets.evm.balance && (
                      <span className="text-xs text-gray-500">Balance: {connectedWallets.evm.balance} ETH</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={disconnectEVMWallet}
                  className="p-2 hover:bg-gray-700 rounded transition-colors ml-2 flex-shrink-0"
                  title="Disconnect wallet"
                >
                  <LogOut className="h-4 w-4 text-gray-400 hover:text-red-400" />
                </button>
              </div>
            )}

            {connectedWallets.starknet && (
              <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg hover:bg-gray-750 transition-colors">
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-semibold">{connectedWallets.starknet.provider}</span>
                      <span className="text-xs px-2 py-0.5 bg-purple-900 text-purple-300 rounded">StarkNet</span>
                    </div>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-xs text-gray-400 font-mono truncate">{formatAddress(connectedWallets.starknet.address, 8, 6)}</span>
                      <button
                        onClick={() => copyToClipboard(connectedWallets.starknet!.address, 'Address')}
                        className="p-1 hover:bg-gray-700 rounded transition-colors"
                        title="Copy address"
                      >
                        <Copy className="h-3 w-3 text-gray-400" />
                      </button>
                    </div>
                  </div>
                </div>
                <button
                  onClick={disconnectStarknetWallet}
                  className="p-2 hover:bg-gray-700 rounded transition-colors ml-2 flex-shrink-0"
                  title="Disconnect wallet"
                >
                  <LogOut className="h-4 w-4 text-gray-400 hover:text-red-400" />
                </button>
              </div>
            )}

            {connectedWallets.zcash && (
              <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg hover:bg-gray-750 transition-colors">
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-semibold">{connectedWallets.zcash.provider}</span>
                      <span className="text-xs px-2 py-0.5 bg-yellow-900 text-yellow-300 rounded">Zcash</span>
                    </div>
                    {connectedWallets.zcash.shieldedAddress && (
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-purple-400">Shielded:</span>
                        <span className="text-xs text-gray-400 font-mono truncate">{formatAddress(connectedWallets.zcash.shieldedAddress, 8, 6)}</span>
                        <button
                          onClick={() => copyToClipboard(connectedWallets.zcash!.shieldedAddress!, 'Shielded Address')}
                          className="p-1 hover:bg-gray-700 rounded transition-colors"
                          title="Copy shielded address"
                        >
                          <Copy className="h-3 w-3 text-gray-400" />
                        </button>
                      </div>
                    )}
                    {connectedWallets.zcash.transparentAddress && (
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-blue-400">Transparent:</span>
                        <span className="text-xs text-gray-400 font-mono truncate">{formatAddress(connectedWallets.zcash.transparentAddress, 8, 6)}</span>
                        <button
                          onClick={() => copyToClipboard(connectedWallets.zcash!.transparentAddress!, 'Transparent Address')}
                          className="p-1 hover:bg-gray-700 rounded transition-colors"
                          title="Copy transparent address"
                        >
                          <Copy className="h-3 w-3 text-gray-400" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>
                <button
                  onClick={disconnectZcashWallet}
                  className="p-2 hover:bg-gray-700 rounded transition-colors ml-2 flex-shrink-0"
                  title="Disconnect wallet"
                >
                  <LogOut className="h-4 w-4 text-gray-400 hover:text-red-400" />
                </button>
              </div>
            )}

            {connectedWallets.monero && (
              <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg hover:bg-gray-750 transition-colors">
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-semibold">{connectedWallets.monero.provider}</span>
                      <span className="text-xs px-2 py-0.5 bg-orange-900 text-orange-300 rounded">Monero</span>
                    </div>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-xs text-gray-400 font-mono truncate">{formatAddress(connectedWallets.monero.address, 8, 6)}</span>
                      <button
                        onClick={() => copyToClipboard(connectedWallets.monero!.address, 'Address')}
                        className="p-1 hover:bg-gray-700 rounded transition-colors"
                        title="Copy address"
                      >
                        <Copy className="h-3 w-3 text-gray-400" />
                      </button>
                    </div>
                  </div>
                </div>
                <button
                  onClick={disconnectMoneroWallet}
                  className="p-2 hover:bg-gray-700 rounded transition-colors ml-2 flex-shrink-0"
                  title="Disconnect wallet"
                >
                  <LogOut className="h-4 w-4 text-gray-400 hover:text-red-400" />
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="mb-6 p-4 bg-gray-900 rounded-lg border border-gray-700">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <Wallet className="h-5 w-5 mr-2" />
          Connect Wallets
        </h3>
        
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-gray-300">EVM Chains</p>
              <span className="text-xs text-gray-500">Ethereum, Polygon, Arbitrum, BSC, etc.</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={connectEVMWallet}
                disabled={!!connectedWallets.evm}
                className="px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Connect EVM Wallet</span>
                {connectedWallets.evm && <CheckCircle className="h-4 w-4" />}
              </button>
            </div>
            {!connectedWallets.evm && (
              <p className="text-xs text-gray-500 mt-2">
                Works with MetaMask, Coinbase Wallet, Trust Wallet, Brave Wallet, and other Web3 providers
              </p>
            )}
          </div>

          <div className="border-t border-gray-800 pt-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-gray-300">StarkNet</p>
              <span className="text-xs text-gray-500">Layer 2 scaling solution</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={connectArgentX}
                disabled={!!connectedWallets.starknet}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Argent X</span>
                {connectedWallets.starknet?.provider === 'Argent X' && <CheckCircle className="h-4 w-4" />}
              </button>
              <button
                onClick={connectBraavos}
                disabled={!!connectedWallets.starknet}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Braavos</span>
                {connectedWallets.starknet?.provider === 'Braavos' && <CheckCircle className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div className="border-t border-gray-800 pt-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-gray-300">Zcash (ZEC)</p>
              <span className="text-xs text-gray-500">Privacy-focused cryptocurrency</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={connectZashiWallet}
                className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Zashi (Mobile)</span>
                <ExternalLink className="h-3 w-3" />
              </button>
              <button
                onClick={connectYWallet}
                disabled={!!connectedWallets.zcash}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>YWallet</span>
                {connectedWallets.zcash && <CheckCircle className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Zcash supports both shielded (private) and transparent transactions
            </p>
          </div>

          <div className="border-t border-gray-800 pt-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-gray-300">Monero (XMR)</p>
              <span className="text-xs text-gray-500">Private, untraceable cryptocurrency</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={connectCakeWallet}
                className="px-4 py-2 bg-orange-700 hover:bg-orange-800 rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Cake Wallet (Mobile)</span>
                <ExternalLink className="h-3 w-3" />
              </button>
              <button
                onClick={connectMonerujo}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Monerujo (Android)</span>
                <ExternalLink className="h-3 w-3" />
              </button>
              <button
                onClick={connectMoneroWallet}
                disabled={!!connectedWallets.monero}
                className="px-4 py-2 bg-orange-800 hover:bg-orange-900 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center space-x-2 text-sm font-medium"
              >
                <Wallet className="h-4 w-4" />
                <span>Monero Desktop</span>
                {connectedWallets.monero && <CheckCircle className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              All Monero transactions are private by default with ring signatures and stealth addresses
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {balances.depositWallets.usdc.map((wallet: any) => (
          <BalanceCard
            key={wallet.network}
            currency="USDC"
            network={wallet.network}
            balance={formatBalance(parseFloat(wallet.balance), 'USDC')}
            address={wallet.address}
            verified={wallet.verified}
            onCopy={() => copyToClipboard(wallet.address, `${wallet.network} address`)}
          />
        ))}

        <BalanceCard
          currency="ZEC"
          network="Shielded"
          balance={formatBalance(balances.depositWallets.zec.shielded.balance, 'ZEC')}
          address={balances.depositWallets.zec.shielded.address}
          verified={balances.depositWallets.zec.shielded.verified}
          onCopy={() => copyToClipboard(balances.depositWallets.zec.shielded.address, 'Zcash shielded address')}
        />
        <BalanceCard
          currency="ZEC"
          network="Transparent"
          balance={formatBalance(balances.depositWallets.zec.transparent.balance, 'ZEC')}
          address={balances.depositWallets.zec.transparent.address}
          verified={balances.depositWallets.zec.transparent.verified}
          onCopy={() => copyToClipboard(balances.depositWallets.zec.transparent.address, 'Zcash transparent address')}
        />

        <BalanceCard
          currency="XMR"
          network="Monero"
          balance={formatBalance(balances.depositWallets.xmr.balance, 'XMR')}
          address={balances.depositWallets.xmr.address}
          verified={balances.depositWallets.xmr.verified}
          onCopy={() => copyToClipboard(balances.depositWallets.xmr.address, 'Monero address')}
        />
      </div>

      {connectedWallets.evm && (
        <div className="mt-6 p-4 bg-gray-900 rounded-lg border border-gray-700">
          <h3 className="text-sm font-semibold mb-3 text-gray-300 flex items-center">
            <Network className="h-4 w-4 mr-2" />
            Switch EVM Network
          </h3>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => switchEVMNetwork('0x1')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Ethereum
            </button>
            <button
              onClick={() => switchEVMNetwork('0x89')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Polygon
            </button>
            <button
              onClick={() => switchEVMNetwork('0xa4b1')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Arbitrum
            </button>
            <button
              onClick={() => switchEVMNetwork('0xa')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Optimism
            </button>
            <button
              onClick={() => switchEVMNetwork('0x38')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              BNB Chain
            </button>
            <button
              onClick={() => switchEVMNetwork('0xa86a')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Avalanche
            </button>
            <button
              onClick={() => switchEVMNetwork('0x2105')}
              className="px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Base
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function BalanceCard({ currency, network, balance, address, verified, onCopy }: any) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-all hover:shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="font-bold text-lg">{currency}</h3>
          <p className="text-sm text-gray-400">{network}</p>
        </div>
        <div className="text-right">
          <div className="text-xl font-mono font-bold">{balance}</div>
          <div className="text-xs text-gray-500">{currency}</div>
        </div>
      </div>
      <div className="flex items-center space-x-2 mb-3">
        <div className="text-xs text-gray-400 font-mono truncate flex-1" title={address}>
          {address || 'Not connected'}
        </div>
        {address && (
          <button
            onClick={onCopy}
            className="p-1 hover:bg-gray-800 rounded transition-colors flex-shrink-0"
            title="Copy address"
          >
            <Copy className="h-3 w-3 text-gray-400" />
          </button>
        )}
      </div>
      <div className="flex items-center justify-between">
        <span className={`text-xs px-2 py-1 rounded font-medium ${
          verified === 'on-chain-private' 
            ? 'bg-purple-900 text-purple-300'
            : verified === 'on-chain'
            ? 'bg-green-900 text-green-300'
            : 'bg-gray-700 text-gray-300'
        }`}>
          {verified}
        </span>
      </div>
    </div>
  );
}