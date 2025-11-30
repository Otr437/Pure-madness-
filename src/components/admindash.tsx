// pages/admin/index.tsx
import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { Wallet, Users, Shield, TrendingUp } from 'lucide-react';
import { api } from '../../lib/api';

export default function AdminDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (!token) {
      router.push('/admin/login');
      return;
    }
    loadDashboard(token);
  }, [router]);

  const loadDashboard = async (token: string) => {
    try {
      const data = await api.getAdminDashboard(token);
      setStats(data);
    } catch (err) {
      localStorage.removeItem('admin_token');
      router.push('/admin/login');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!stats) return null;

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Admin Dashboard</h1>
      
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={<Wallet className="h-8 w-8" />}
          title="Total Payments"
          value={stats.overview.totalPayments.toString()}
          description="All time payments"
        />
        <StatCard
          icon={<TrendingUp className="h-8 w-8" />}
          title="Confirmed Payments"
          value={stats.overview.confirmedPayments.toString()}
          description="Successfully verified"
        />
        <StatCard
          icon={<Users className="h-8 w-8" />}
          title="Total Revenue"
          value={`$${stats.overview.totalRevenue}`}
          description="USD equivalent"
        />
        <StatCard
          icon={<Shield className="h-8 w-8" />}
          title="Active Privacy Routes"
          value={stats.overview.activePrivacyRoutes.toString()}
          description="In progress"
        />
      </div>

      {/* System Health */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-xl font-bold mb-4">System Health</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {Object.entries(stats.system || {}).map(([service, status]: [string, any]) => (
            <div key={service} className="text-center p-4 bg-gray-900 rounded-lg">
              <div className="text-sm text-gray-400 capitalize mb-2">{service.replace('_', ' ')}</div>
              <div className={`text-lg font-bold ${
                status === 'connected' ? 'text-green-500' : 'text-red-500'
              }`}>
                {status}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, title, value, description }: any) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
          <p className="text-xs text-gray-500 mt-1">{description}</p>
        </div>
        <div className="text-blue-500">
          {icon}
        </div>
      </div>
    </div>
  );
}