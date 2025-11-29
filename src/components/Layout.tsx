// components/Layout.tsx
import React from 'react'
import { Header } from './Header'
import { Footer } from './Footer'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
      <div className="fixed inset-0 bg-gradient-to-br from-blue-900/10 via-transparent to-purple-900/10 pointer-events-none" />
      <div className="relative z-10">
        <Header />
        <main className="container mx-auto px-4 py-8 min-h-screen">
          {children}
        </main>
        <Footer />
      </div>
    </div>
  )
}