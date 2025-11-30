// components/Header.tsx
import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { Shield, Wallet, BarChart3, Settings, LogOut } from 'lucide-react'

export function Header() {
  const router = useRouter()
  const isAuthenticated = false

  const isActive = (path: string) => router.pathname === path

  return (
    <header className="border-b border-gray-800 bg-black/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link href="/" className="flex items-center space-x-3 group">
            <div className="p-2 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg group-hover:scale-110 transition-transform">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <span className="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
                X402 Protocol
              </span>
              <div className="text-xs text-gray-400">Production Ready</div>
            </div>
          </Link>
          
          <nav className="flex items-center space-x-1">
            <Link 
              href="/payment" 
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
                isActive('/payment') 
                  ? 'bg-blue-600 text-white shadow-lg' 
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Wallet className="h-4 w-4" />
              <span>Payments</span>
            </Link>
            
            <Link 
              href="/wallet" 
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
                isActive('/wallet') 
                  ? 'bg-blue-600 text-white shadow-lg' 
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <BarChart3 className="h-4 w-4" />
              <span>Wallet</span>
            </Link>

            {isAuthenticated ? (
              <div className="flex items-center space-x-3 ml-4 pl-4 border-l border-gray-700">
                <span className="text-sm text-gray-300">admin</span>
                <button className="flex items-center space-x-2 px-3 py-2 text-red-400 hover:bg-red-900/20 rounded-lg transition-colors">
                  <LogOut className="h-4 w-4" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <Link 
                href="/admin/login" 
                className="flex items-center space-x-2 px-4 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-lg transition-colors ml-4"
              >
                <Settings className="h-4 w-4" />
                <span>Admin Login</span>
              </Link>
            )}
          </nav>
        </div>
      </div>
    </header>
  )
}