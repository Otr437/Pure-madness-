// pages/index.tsx
import React from 'react';
import Link from 'next/link';
import { ArrowRight, Shield, Zap, Lock, Globe } from 'lucide-react';

export default function Home() {
  return (
    <div className="space-y-16">
      {/* Hero Section */}
      <section className="text-center space-y-8">
        <h1 className="text-5xl md:text-6xl font-bold">
          <span className="bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
            X402 Protocol
          </span>
        </h1>
        <p className="text-xl text-gray-300 max-w-2xl mx-auto">
          Enterprise-grade payment protocol with multi-chain USDC, Zcash, Monero, 
          and advanced privacy routing for production applications.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link 
            href="/payment" 
            className="px-8 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors flex items-center justify-center space-x-2"
          >
            <span>Make Payment</span>
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link 
            href="/admin" 
            className="px-8 py-3 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors"
          >
            Admin Dashboard
          </Link>
        </div>
      </section>

      {/* Features Grid */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="text-blue-500 mb-4">
            <Globe className="h-8 w-8" />
          </div>
          <h3 className="text-xl font-bold mb-2">Multi-Chain</h3>
          <p className="text-gray-400">USDC on Base, Polygon, StarkNet with seamless cross-chain support</p>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="text-blue-500 mb-4">
            <Shield className="h-8 w-8" />
          </div>
          <h3 className="text-xl font-bold mb-2">Privacy First</h3>
          <p className="text-gray-400">Zcash shielded transactions & Monero integration with privacy routing</p>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="text-blue-500 mb-4">
            <Zap className="h-8 w-8" />
          </div>
          <h3 className="text-xl font-bold mb-2">Enterprise Ready</h3>
          <p className="text-gray-400">Production-grade with admin controls, audit logs, and monitoring</p>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-blue-500 transition-colors">
          <div className="text-blue-500 mb-4">
            <Lock className="h-8 w-8" />
          </div>
          <h3 className="text-xl font-bold mb-2">Secure</h3>
          <p className="text-gray-400">On-chain verification, deferred payments, and MCP compatibility</p>
        </div>
      </section>

      {/* Stats Section */}
      <section className="bg-gray-800 rounded-xl p-8 border border-gray-700 text-center">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          <div>
            <div className="text-3xl font-bold text-blue-500">3</div>
            <div className="text-gray-400 mt-1">Blockchains</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-blue-500">3</div>
            <div className="text-gray-400 mt-1">Currencies</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-blue-500">100%</div>
            <div className="text-gray-400 mt-1">On-Chain</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-blue-500">24/7</div>
            <div className="text-gray-400 mt-1">Monitoring</div>
          </div>
        </div>
      </section>
    </div>
  );
}