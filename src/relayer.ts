// ============================================================================
// RELAYER INFRASTRUCTURE - FULL IMPLEMENTATION
// ============================================================================

import {
  Field,
  Poseidon,
  Bool,
  UInt64,
  UInt32,
  PublicKey,
  Signature,
  PrivateKey,
  Struct,
} from 'o1js';

// ============================================================================
// RELAYER PAYMENT STRUCTURE
// ============================================================================

export class RelayerPayment extends Struct({
  feeAmount: UInt64,
  relayerPubKey: PublicKey,
  relayerSignature: Signature,
  deadline: UInt64,
}) {
  verifySignature(commitmentHash: Field): Bool {
    const fields = [
      this.feeAmount.value,
      commitmentHash,
      this.deadline.value,
    ];
    
    return this.relayerSignature.verify(this.relayerPubKey, fields);
  }

  isExpired(currentTime: UInt64): Bool {
    return currentTime.greaterThan(this.deadline);
  }

  toJSON(): {
    feeAmount: string;
    relayerPubKey: string;
    relayerSignature: { r: string; s: string };
    deadline: string;
  } {
    return {
      feeAmount: this.fee