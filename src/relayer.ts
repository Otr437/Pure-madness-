// ============================================================================
// X402 RELAYER INFRASTRUCTURE - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 6 of 8
// Full relayer payment system, fee management, cross-chain execution
// Relayer registry, reputation tracking, automated withdrawals
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
      feeAmount: this.feeAmount.toString(),
      relayerPubKey: this.relayerPubKey.toBase58(),
      relayerSignature: {
        r: this.relayerSignature.r.toString(),
        s: this.relayerSignature.s.toString(),
      },
      deadline: this.deadline.toString(),
    };
  }

  static fromJSON(json: {
    feeAmount: string;
    relayerPubKey: string;
    relayerSignature: { r: string; s: string };
    deadline: string;
  }): RelayerPayment {
    return new RelayerPayment({
      feeAmount: UInt64.from(json.feeAmount),
      relayerPubKey: PublicKey.fromBase58(json.relayerPubKey),
      relayerSignature: Signature.fromFields([
        Field.from(json.relayerSignature.r),
        Field.from(json.relayerSignature.s),
      ]),
      deadline: UInt64.from(json.deadline),
    });
  }

  static create(
    feeAmount: bigint,
    relayerPrivateKey: PrivateKey,
    commitmentHash: Field,
    deadline: bigint
  ): RelayerPayment {
    const relayerPubKey = relayerPrivateKey.toPublicKey();
    const feeAmountField = UInt64.from(feeAmount);
    const deadlineField = UInt64.from(deadline);

    const fields = [
      feeAmountField.value,
      commitmentHash,
      deadlineField.value,
    ];

    const relayerSignature = Signature.create(relayerPrivateKey, fields);

    return new RelayerPayment({
      feeAmount: feeAmountField,
      relayerPubKey,
      relayerSignature,
      deadline: deadlineField,
    });
  }
}

// ============================================================================
// RELAYER INFO
// ============================================================================

export class RelayerInfo extends Struct({
  publicKey: PublicKey,
  chainId: UInt32,
  minimumFee: UInt64,
  maximumFee: UInt64,
  reputation: UInt32,
  totalTransactions: UInt64,
  successfulTransactions: UInt64,
  registrationTime: UInt64,
  lastActiveTime: UInt64,
  isActive: Bool,
}) {
  getSuccessRate(): number {
    const total = this.totalTransactions.value.toBigInt();
    const successful = this.successfulTransactions.value.toBigInt();
    
    if (total === 0n) return 0;
    return Number((successful * 100n) / total);
  }

  toJSON(): {
    publicKey: string;
    chainId: string;
    minimumFee: string;
    maximumFee: string;
    reputation: string;
    totalTransactions: string;
    successfulTransactions: string;
    registrationTime: string;
    lastActiveTime: string;
    isActive: boolean;
    successRate: number;
  } {
    return {
      publicKey: this.publicKey.toBase58(),
      chainId: this.chainId.toString(),
      minimumFee: this.minimumFee.toString(),
      maximumFee: this.maximumFee.toString(),
      reputation: this.reputation.toString(),
      totalTransactions: this.totalTransactions.toString(),
      successfulTransactions: this.successfulTransactions.toString(),
      registrationTime: this.registrationTime.toString(),
      lastActiveTime: this.lastActiveTime.toString(),
      isActive: this.isActive.toBoolean(),
      successRate: this.getSuccessRate(),
    };
  }

  static fromJSON(json: {
    publicKey: string;
    chainId: string;
    minimumFee: string;
    maximumFee: string;
    reputation: string;
    totalTransactions: string;
    successfulTransactions: string;
    registrationTime: string;
    lastActiveTime: string;
    isActive: boolean;
  }): RelayerInfo {
    return new RelayerInfo({
      publicKey: PublicKey.fromBase58(json.publicKey),
      chainId: UInt32.from(json.chainId),
      minimumFee: UInt64.from(json.minimumFee),
      maximumFee: UInt64.from(json.maximumFee),
      reputation: UInt32.from(json.reputation),
      totalTransactions: UInt64.from(json.totalTransactions),
      successfulTransactions: UInt64.from(json.successfulTransactions),
      registrationTime: UInt64.from(json.registrationTime),
      lastActiveTime: UInt64.from(json.lastActiveTime),
      isActive: Bool(json.isActive),
    });
  }
}

// ============================================================================
// RELAYER REGISTRY
// ============================================================================

export class RelayerRegistry {
  private relayers: Map<string, RelayerInfo>;
  private relayersByChain: Map<number, Set<string>>;
  private activeRelayers: Set<string>;

  constructor() {
    this.relayers = new Map();
    this.relayersByChain = new Map();
    this.activeRelayers = new Set();
  }

  register(
    publicKey: PublicKey,
    chainId: number,
    minimumFee: bigint,
    maximumFee: bigint
  ): RelayerInfo {
    const key = publicKey.toBase58();

    if (this.relayers.has(key)) {
      throw new Error('Relayer already registered');
    }

    const currentTime = UInt64.from(BigInt(Math.floor(Date.now() / 1000)));

    const info = new RelayerInfo({
      publicKey,
      chainId: UInt32.from(chainId),
      minimumFee: UInt64.from(minimumFee),
      maximumFee: UInt64.from(maximumFee),
      reputation: UInt32.from(100),
      totalTransactions: UInt64.from(0),
      successfulTransactions: UInt64.from(0),
      registrationTime: currentTime,
      lastActiveTime: currentTime,
      isActive: Bool(true),
    });

    this.relayers.set(key, info);
    this.activeRelayers.add(key);

    if (!this.relayersByChain.has(chainId)) {
      this.relayersByChain.set(chainId, new Set());
    }
    this.relayersByChain.get(chainId)!.add(key);

    return info;
  }

  get(publicKey: PublicKey): RelayerInfo | undefined {
    return this.relayers.get(publicKey.toBase58());
  }

  has(publicKey: PublicKey): boolean {
    return this.relayers.has(publicKey.toBase58());
  }

  getByChain(chainId: number): RelayerInfo[] {
    const keys = this.relayersByChain.get(chainId);
    if (!keys) return [];

    return Array.from(keys)
      .map(key => this.relayers.get(key))
      .filter((r): r is RelayerInfo => r !== undefined);
  }

  getActive(): RelayerInfo[] {
    return Array.from(this.activeRelayers)
      .map(key => this.relayers.get(key))
      .filter((r): r is RelayerInfo => r !== undefined);
  }

  getActiveByChain(chainId: number): RelayerInfo[] {
    return this.getByChain(chainId).filter(r => r.isActive.toBoolean());
  }

  updateActivity(publicKey: PublicKey, success: boolean): void {
    const key = publicKey.toBase58();
    const info = this.relayers.get(key);

    if (!info) {
      throw new Error('Relayer not found');
    }

    const currentTime = UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
    const newTotal = info.totalTransactions.add(UInt64.from(1));
    const newSuccessful = success 
      ? info.successfulTransactions.add(UInt64.from(1))
      : info.successfulTransactions;

    const successRate = Number(newSuccessful.value.toBigInt() * 100n / newTotal.value.toBigInt());
    let newReputation = info.reputation.value.toBigInt();

    if (success) {
      newReputation = newReputation < 1000n ? newReputation + 1n : 1000n;
    } else {
      newReputation = newReputation > 0n ? newReputation - 5n : 0n;
    }

    const updated = new RelayerInfo({
      publicKey: info.publicKey,
      chainId: info.chainId,
      minimumFee: info.minimumFee,
      maximumFee: info.maximumFee,
      reputation: UInt32.from(newReputation),
      totalTransactions: newTotal,
      successfulTransactions: newSuccessful,
      registrationTime: info.registrationTime,
      lastActiveTime: currentTime,
      isActive: info.isActive,
    });

    this.relayers.set(key, updated);
  }

  deactivate(publicKey: PublicKey): void {
    const key = publicKey.toBase58();
    const info = this.relayers.get(key);

    if (!info) {
      throw new Error('Relayer not found');
    }

    const updated = new RelayerInfo({
      publicKey: info.publicKey,
      chainId: info.chainId,
      minimumFee: info.minimumFee,
      maximumFee: info.maximumFee,
      reputation: info.reputation,
      totalTransactions: info.totalTransactions,
      successfulTransactions: info.successfulTransactions,
      registrationTime: info.registrationTime,
      lastActiveTime: info.lastActiveTime,
      isActive: Bool(false),
    });

    this.relayers.set(key, updated);
    this.activeRelayers.delete(key);
  }

  activate(publicKey: PublicKey): void {
    const key = publicKey.toBase58();
    const info = this.relayers.get(key);

    if (!info) {
      throw new Error('Relayer not found');
    }

    const updated = new RelayerInfo({
      publicKey: info.publicKey,
      chainId: info.chainId,
      minimumFee: info.minimumFee,
      maximumFee: info.maximumFee,
      reputation: info.reputation,
      totalTransactions: info.totalTransactions,
      successfulTransactions: info.successfulTransactions,
      registrationTime: info.registrationTime,
      lastActiveTime: info.lastActiveTime,
      isActive: Bool(true),
    });

    this.relayers.set(key, updated);
    this.activeRelayers.add(key);
  }

  updateFees(publicKey: PublicKey, minimumFee: bigint, maximumFee: bigint): void {
    const key = publicKey.toBase58();
    const info = this.relayers.get(key);

    if (!info) {
      throw new Error('Relayer not found');
    }

    const updated = new RelayerInfo({
      publicKey: info.publicKey,
      chainId: info.chainId,
      minimumFee: UInt64.from(minimumFee),
      maximumFee: UInt64.from(maximumFee),
      reputation: info.reputation,
      totalTransactions: info.totalTransactions,
      successfulTransactions: info.successfulTransactions,
      registrationTime: info.registrationTime,
      lastActiveTime: info.lastActiveTime,
      isActive: info.isActive,
    });

    this.relayers.set(key, updated);
  }

  getBestRelayer(chainId: number, amount: bigint): RelayerInfo | null {
    const relayers = this.getActiveByChain(chainId);

    if (relayers.length === 0) return null;

    const eligible = relayers.filter(r => {
      const min = r.minimumFee.value.toBigInt();
      const max = r.maximumFee.value.toBigInt();
      return amount >= min && amount <= max;
    });

    if (eligible.length === 0) return null;

    eligible.sort((a, b) => {
      const repA = Number(a.reputation.value.toString());
      const repB = Number(b.reputation.value.toString());
      return repB - repA;
    });

    return eligible[0];
  }

  exportToJSON(): string {
    const data = Array.from(this.relayers.values()).map(r => r.toJSON());
    return JSON.stringify(data, null, 2);
  }

  importFromJSON(json: string): void {
    const data = JSON.parse(json);
    this.clear();

    data.forEach((item: any) => {
      const info = RelayerInfo.fromJSON(item);
      const key = info.publicKey.toBase58();
      this.relayers.set(key, info);

      if (info.isActive.toBoolean()) {
        this.activeRelayers.add(key);
      }

      const chainId = Number(info.chainId.value.toString());
      if (!this.relayersByChain.has(chainId)) {
        this.relayersByChain.set(chainId, new Set());
      }
      this.relayersByChain.get(chainId)!.add(key);
    });
  }

  clear(): void {
    this.relayers.clear();
    this.relayersByChain.clear();
    this.activeRelayers.clear();
  }

  size(): number {
    return this.relayers.size;
  }

  getStatistics(): {
    totalRelayers: number;
    activeRelayers: number;
    relayersByChain: Record<number, number>;
    averageReputation: number;
    averageSuccessRate: number;
  } {
    const stats = {
      totalRelayers: this.relayers.size,
      activeRelayers: this.activeRelayers.size,
      relayersByChain: {} as Record<number, number>,
      averageReputation: 0,
      averageSuccessRate: 0,
    };

    if (this.relayers.size === 0) return stats;

    let totalReputation = 0;
    let totalSuccessRate = 0;

    this.relayersByChain.forEach((relayers, chainId) => {
      stats.relayersByChain[chainId] = relayers.size;
    });

    this.relayers.forEach(info => {
      totalReputation += Number(info.reputation.value.toString());
      totalSuccessRate += info.getSuccessRate();
    });

    stats.averageReputation = totalReputation / this.relayers.size;
    stats.averageSuccessRate = totalSuccessRate / this.relayers.size;

    return stats;
  }
}

// ============================================================================
// WITHDRAWAL REQUEST
// ============================================================================

export class WithdrawalRequest extends Struct({
  commitmentHash: Field,
  nullifierHash: Field,
  recipientHash: Field,
  amount: UInt64,
  targetChain: UInt32,
  relayerPayment: RelayerPayment,
  timestamp: UInt64,
  status: Field,
}) {
  static STATUS_PENDING = Field(0);
  static STATUS_PROCESSING = Field(1);
  static STATUS_COMPLETED = Field(2);
  static STATUS_FAILED = Field(3);

  toJSON(): {
    commitmentHash: string;
    nullifierHash: string;
    recipientHash: string;
    amount: string;
    targetChain: string;
    relayerPayment: any;
    timestamp: string;
    status: string;
  } {
    return {
      commitmentHash: this.commitmentHash.toString(),
      nullifierHash: this.nullifierHash.toString(),
      recipientHash: this.recipientHash.toString(),
      amount: this.amount.toString(),
      targetChain: this.targetChain.toString(),
      relayerPayment: this.relayerPayment.toJSON(),
      timestamp: this.timestamp.toString(),
      status: this.status.toString(),
    };
  }
}

// ============================================================================
// RELAYER QUEUE
// ============================================================================

export class RelayerQueue {
  private queue: WithdrawalRequest[];
  private processing: Map<string, WithdrawalRequest>;
  private completed: Map<string, WithdrawalRequest>;
  private failed: Map<string, WithdrawalRequest>;

  constructor() {
    this.queue = [];
    this.processing = new Map();
    this.completed = new Map();
    this.failed = new Map();
  }

  enqueue(request: WithdrawalRequest): void {
    this.queue.push(request);
    this.queue.sort((a, b) => {
      const feeA = a.relayerPayment.feeAmount.value.toBigInt();
      const feeB = b.relayerPayment.feeAmount.value.toBigInt();
      return Number(feeB - feeA);
    });
  }

  dequeue(): WithdrawalRequest | undefined {
    const request = this.queue.shift();
    if (request) {
      this.processing.set(request.nullifierHash.toString(), request);
    }
    return request;
  }

  markCompleted(nullifierHash: Field): void {
    const key = nullifierHash.toString();
    const request = this.processing.get(key);
    if (request) {
      this.processing.delete(key);
      this.completed.set(key, request);
    }
  }

  markFailed(nullifierHash: Field): void {
    const key = nullifierHash.toString();
    const request = this.processing.get(key);
    if (request) {
      this.processing.delete(key);
      this.failed.set(key, request);
    }
  }

  size(): number {
    return this.queue.length;
  }

  processingCount(): number {
    return this.processing.size;
  }

  completedCount(): number {
    return this.completed.size;
  }

  failedCount(): number {
    return this.failed.size;
  }

  clear(): void {
    this.queue = [];
    this.processing.clear();
    this.completed.clear();
    this.failed.clear();
  }

  getStatistics(): {
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    successRate: number;
  } {
    const total = this.completed.size + this.failed.size;
    const successRate = total === 0 ? 0 : (this.completed.size / total) * 100;

    return {
      pending: this.queue.length,
      processing: this.processing.size,
      completed: this.completed.size,
      failed: this.failed.size,
      successRate,
    };
  }
}

// ============================================================================
// FEE CALCULATOR
// ============================================================================

export class FeeCalculator {
  static BASE_FEE_BPS = 10n;
  static MIN_FEE = 1000n;
  static MAX_FEE_BPS = 500n;

  static calculateRelayerFee(amount: bigint, chainId: number): bigint {
    const baseFee = (amount * this.BASE_FEE_BPS) / 10000n;
    
    const chainMultipliers: Record<number, bigint> = {
      1: 100n,
      137: 50n,
      42161: 75n,
      10: 75n,
      43114: 100n,
      56: 50n,
      8453: 75n,
      324: 100n,
      534352: 100n,
    };

    const multiplier = chainMultipliers[chainId] || 100n;
    const adjustedFee = (baseFee * multiplier) / 100n;

    const maxFee = (amount * this.MAX_FEE_BPS) / 10000n;
    const finalFee = adjustedFee > maxFee ? maxFee : adjustedFee;

    return finalFee < this.MIN_FEE ? this.MIN_FEE : finalFee;
  }

  static calculateProtocolFee(amount: bigint, feeBps: number): bigint {
    return (amount * BigInt(feeBps)) / 10000n;
  }

  static calculateNetAmount(amount: bigint, relayerFee: bigint, protocolFee: bigint): bigint {
    return amount - relayerFee - protocolFee;
  }

  static validateFee(fee: bigint, amount: bigint): boolean {
    const maxAllowed = (amount * this.MAX_FEE_BPS) / 10000n;
    return fee >= this.MIN_FEE && fee <= maxAllowed;
  }
}