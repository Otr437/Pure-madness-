// pages/wallet.tsx
import React from 'react';
import WalletBalances from '../components/WalletBalances';

export default function WalletPage() {
  return (
    <div className="space-y-8">
      <h1 className="text-3xl font-bold">Wallet Overview</h1>
      <WalletBalances />
    </div>
  );
}