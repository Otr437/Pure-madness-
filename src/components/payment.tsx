// pages/payment.tsx
import React from 'react';
import PaymentRequest from '../components/PaymentRequest';

export default function PaymentPage() {
  return (
    <div className="space-y-8">
      <h1 className="text-3xl font-bold">Make a Payment</h1>
      <PaymentRequest amount={1.0} resource="premium-data-access" />
    </div>
  );
}