// components/Footer.tsx
import React from 'react'
import { Github, Twitter, Mail, Shield } from 'lucide-react'

export function Footer() {
  return (
    <footer className="border-t border-gray-800 bg-black/50 mt-16">
      <div className="container mx-auto px-4 py-8">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center space-x-2 mb-4 md:mb-0">
            <div className="p-2 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-lg font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
              X402 Protocol
            </span>
          </div>
          
          <div className="flex items-center space-x-4 text-gray-400">
            <span className="text-sm">Production v1.0.0</span>
            <div className="w-1 h-1 bg-gray-600 rounded-full"></div>
            <span className="text-sm">Multi-Chain Payments</span>
            <div className="w-1 h-1 bg-gray-600 rounded-full"></div>
            <span className="text-sm">Privacy First</span>
          </div>
          
          <div className="flex items-center space-x-4 mt-4 md:mt-0">
            <a href="#" className="text-gray-400 hover:text-white transition-colors">
              <Github className="h-5 w-5" />
            </a>
            <a href="#" className="text-gray-400 hover:text-white transition-colors">
              <Twitter className="h-5 w-5" />
            </a>
            <a href="#" className="text-gray-400 hover:text-white transition-colors">
              <Mail className="h-5 w-5" />
            </a>
          </div>
        </div>
        
        <div className="border-t border-gray-800 mt-6 pt-6 text-center">
          <p className="text-sm text-gray-500">
            © 2024 X402 Protocol. Enterprise-grade payment infrastructure with USDC, Zcash, and Monero.
            Built for production with privacy routing and multi-chain support.
          </p>
        </div>
      </div>
    </footer>
  )
}