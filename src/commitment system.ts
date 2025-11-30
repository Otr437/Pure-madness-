// ============================================================================
// X402 COMMITMENT SYSTEM - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 4 of 8
// Full commitment creation, verification, storage, and management
// Builder pattern, validation, serialization
// ============================================================================

import {
  Field,
  Poseidon,
  Bool,
  UInt64,
  UInt32,
  Struct,
  Provable,
  PublicKey,
} from 'o1js';

// ============================================================================
// TRANSFER COMMITMENT STRUCTURE
// ============================================================================

export class TransferCommitment extends Struct({
  hash: Field,
  amount: UInt64,
  recipientHash: Field,
  sourceChain: UInt32,
  targetChain: UInt32,
  timestamp: UInt64,
  nonce: Field,
}) {
  static create(
    amount: UInt64,
    recipient: Field,
    secret: Field,
    sourceChain: UInt32,
    targetChain: UInt32,
    timestamp: UInt64,
    nonce: Field
  ): TransferCommitment {
    const hash = Poseidon.hash([
      amount.value,
      recipient,
      secret,
      sourceChain.value,
      targetChain.value,
      timestamp.value,
      nonce,
    ]);

    const recipientHash = Poseidon.hash([recipient, secret]);

    return new TransferCommitment({
      hash,
      amount,
      recipientHash,
      sourceChain,
      targetChain,
      timestamp,
      nonce,
    });
  }

  verify(recipient: Field, secret: Field): Bool {
    const recomputedHash = Poseidon.hash([
      this.amount.value,
      recipient,
      secret,
      this.sourceChain.value,
      this.targetChain.value,
      this.timestamp.value,
      this.nonce,
    ]);

    const recomputedRecipientHash = Poseidon.hash([recipient, secret]);

    return this.hash.equals(recomputedHash).and(
      this.recipientHash.equals(recomputedRecipientHash)
    );
  }

  isExpired(currentTime: UInt64): Bool {
    const EXPIRY_SECONDS = UInt64.from(86400);
    const expiryTime = this.timestamp.add(EXPIRY_SECONDS);
    return currentTime.greaterThan(expiryTime);
  }

  toJSON(): {
    hash: string;
    amount: string;
    recipientHash: string;
    sourceChain: string;
    targetChain: string;
    timestamp: string;
    nonce: string;
  } {
    return {
      hash: this.hash.toString(),
      amount: this.amount.toString(),
      recipientHash: this.recipientHash.toString(),
      sourceChain: this.sourceChain.toString(),
      targetChain: this.targetChain.toString(),
      timestamp: this.timestamp.toString(),
      nonce: this.nonce.toString(),
    };
  }

  static fromJSON(json: {
    hash: string;
    amount: string;
    recipientHash: string;
    sourceChain: string;
    targetChain: string;
    timestamp: string;
    nonce: string;
  }): TransferCommitment {
    return new TransferCommitment({
      hash: Field.from(json.hash),
      amount: UInt64.from(json.amount),
      recipientHash: Field.from(json.recipientHash),
      sourceChain: UInt32.from(json.sourceChain),
      targetChain: UInt32.from(json.targetChain),
      timestamp: UInt64.from(json.timestamp),
      nonce: Field.from(json.nonce),
    });
  }

  equals(other: TransferCommitment): boolean {
    return this.hash.equals(other.hash).toBoolean();
  }

  toString(): string {
    return JSON.stringify(this.toJSON(), null, 2);
  }
}

// ============================================================================
// COMMITMENT BUILDER
// ============================================================================

export class CommitmentBuilder {
  private amount?: UInt64;
  private recipient?: Field;
  private secret?: Field;
  private sourceChain?: UInt32;
  private targetChain?: UInt32;
  private timestamp?: UInt64;
  private nonce?: Field;

  setAmount(amount: bigint | UInt64 | number): CommitmentBuilder {
    if (amount instanceof UInt64) {
      this.amount = amount;
    } else if (typeof amount === 'number') {
      this.amount = UInt64.from(BigInt(amount));
    } else {
      this.amount = UInt64.from(amount);
    }
    return this;
  }

  setRecipient(recipient: Field | string | bigint | PublicKey): CommitmentBuilder {
    if (recipient instanceof Field) {
      this.recipient = recipient;
    } else if (recipient instanceof PublicKey) {
      this.recipient = Poseidon.hash([recipient.x, recipient.y]);
    } else if (typeof recipient === 'string') {
      const clean = recipient.startsWith('0x') ? recipient.slice(2) : recipient;
      this.recipient = Field.from(BigInt('0x' + clean));
    } else {
      this.recipient = Field.from(recipient);
    }
    return this;
  }

  setSecret(secret: Field | string | bigint): CommitmentBuilder {
    if (secret instanceof Field) {
      this.secret = secret;
    } else if (typeof secret === 'string') {
      const clean = secret.startsWith('0x') ? secret.slice(2) : secret;
      this.secret = Field.from(BigInt('0x' + clean));
    } else {
      this.secret = Field.from(secret);
    }
    return this;
  }

  setSourceChain(chain: number | UInt32): CommitmentBuilder {
    this.sourceChain = typeof chain === 'number' ? UInt32.from(chain) : chain;
    return this;
  }

  setTargetChain(chain: number | UInt32): CommitmentBuilder {
    this.targetChain = typeof chain === 'number' ? UInt32.from(chain) : chain;
    return this;
  }

  setTimestamp(timestamp: bigint | UInt64 | number): CommitmentBuilder {
    if (timestamp instanceof UInt64) {
      this.timestamp = timestamp;
    } else if (typeof timestamp === 'number') {
      this.timestamp = UInt64.from(BigInt(timestamp));
    } else {
      this.timestamp = UInt64.from(timestamp);
    }
    return this;
  }

  setNonce(nonce: Field | string | bigint): CommitmentBuilder {
    if (nonce instanceof Field) {
      this.nonce = nonce;
    } else if (typeof nonce === 'string') {
      const clean = nonce.startsWith('0x') ? nonce.slice(2) : nonce;
      this.nonce = Field.from(BigInt('0x' + clean));
    } else {
      this.nonce = Field.from(nonce);
    }
    return this;
  }

  useCurrentTimestamp(): CommitmentBuilder {
    this.timestamp = UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
    return this;
  }

  generateSecret(): CommitmentBuilder {
    this.secret = Field.random();
    return this;
  }

  generateNonce(): CommitmentBuilder {
    this.nonce = Field.random();
    return this;
  }

  build(): TransferCommitment {
    if (!this.amount) throw new Error('Amount not set');
    if (!this.recipient) throw new Error('Recipient not set');
    if (!this.secret) throw new Error('Secret not set');
    if (!this.sourceChain) throw new Error('Source chain not set');
    if (!this.targetChain) throw new Error('Target chain not set');
    if (!this.timestamp) throw new Error('Timestamp not set');
    if (!this.nonce) throw new Error('Nonce not set');

    return TransferCommitment.create(
      this.amount,
      this.recipient,
      this.secret,
      this.sourceChain,
      this.targetChain,
      this.timestamp,
      this.nonce
    );
  }

  buildWithDefaults(): TransferCommitment {
    if (!this.timestamp) this.useCurrentTimestamp();
    if (!this.secret) this.generateSecret();
    if (!this.nonce) this.generateNonce();

    return this.build();
  }

  reset(): CommitmentBuilder {
    this.amount = undefined;
    this.recipient = undefined;
    this.secret = undefined;
    this.sourceChain = undefined;
    this.targetChain = undefined;
    this.timestamp = undefined;
    this.nonce = undefined;
    return this;
  }
}

// ============================================================================
// COMMITMENT VALIDATOR
// ============================================================================

export class CommitmentValidator {
  static MIN_AMOUNT = 1n;
  static MAX_AMOUNT = 1_000_000_000_000_000n;
  static MAX_AGE_SECONDS = 86400n;

  private static SUPPORTED_CHAINS = new Set([
    1, 137, 42161, 10, 43114, 56, 8453, 324, 534352,
    11155111, 80001, 421613, 420, 43113, 97, 84531, 280, 534351,
  ]);

  static validateAmount(amount: UInt64): { valid: boolean; error?: string } {
    const value = amount.value.toBigInt();
    
    if (value < this.MIN_AMOUNT) {
      return { valid: false, error: `Amount ${value} below minimum ${this.MIN_AMOUNT}` };
    }
    
    if (value > this.MAX_AMOUNT) {
      return { valid: false, error: `Amount ${value} exceeds maximum ${this.MAX_AMOUNT}` };
    }
    
    return { valid: true };
  }

  static validateChains(
    sourceChain: UInt32,
    targetChain: UInt32
  ): { valid: boolean; error?: string } {
    const source = Number(sourceChain.value.toString());
    const target = Number(targetChain.value.toString());

    if (source === target) {
      return { valid: false, error: 'Source and target chains must differ' };
    }
    
    if (!this.SUPPORTED_CHAINS.has(source)) {
      return { valid: false, error: `Source chain ${source} not supported` };
    }
    
    if (!this.SUPPORTED_CHAINS.has(target)) {
      return { valid: false, error: `Target chain ${target} not supported` };
    }
    
    return { valid: true };
  }

  static validateTimestamp(
    timestamp: UInt64,
    currentTime: bigint
  ): { valid: boolean; error?: string } {
    const timestampValue = timestamp.value.toBigInt();
    
    if (timestampValue > currentTime) {
      return { valid: false, error: 'Timestamp is in the future' };
    }
    
    const age = currentTime - timestampValue;
    if (age > this.MAX_AGE_SECONDS) {
      return { valid: false, error: `Commitment expired (age: ${age}s)` };
    }
    
    return { valid: true };
  }

  static validateRecipient(recipient: Field): { valid: boolean; error?: string } {
    const value = recipient.toBigInt();
    
    if (value === 0n) {
      return { valid: false, error: 'Recipient cannot be zero' };
    }
    
    return { valid: true };
  }

  static validateSecret(secret: Field): { valid: boolean; error?: string } {
    const value = secret.toBigInt();
    
    if (value === 0n) {
      return { valid: false, error: 'Secret cannot be zero' };
    }
    
    return { valid: true };
  }

  static validateNonce(nonce: Field): { valid: boolean; error?: string } {
    const value = nonce.toBigInt();
    
    if (value === 0n) {
      return { valid: false, error: 'Nonce cannot be zero' };
    }
    
    return { valid: true };
  }

  static validateCommitment(
    commitment: TransferCommitment,
    currentTime?: bigint
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const now = currentTime ?? BigInt(Math.floor(Date.now() / 1000));
    
    const amountValidation = this.validateAmount(commitment.amount);
    if (!amountValidation.valid && amountValidation.error) {
      errors.push(amountValidation.error);
    }
    
    const chainValidation = this.validateChains(commitment.sourceChain, commitment.targetChain);
    if (!chainValidation.valid && chainValidation.error) {
      errors.push(chainValidation.error);
    }
    
    const timestampValidation = this.validateTimestamp(commitment.timestamp, now);
    if (!timestampValidation.valid && timestampValidation.error) {
      errors.push(timestampValidation.error);
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  static validateCommitmentWithSecrets(
    commitment: TransferCommitment,
    recipient: Field,
    secret: Field,
    currentTime?: bigint
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    const basicValidation = this.validateCommitment(commitment, currentTime);
    errors.push(...basicValidation.errors);

    const recipientValidation = this.validateRecipient(recipient);
    if (!recipientValidation.valid && recipientValidation.error) {
      errors.push(recipientValidation.error);
    }

    const secretValidation = this.validateSecret(secret);
    if (!secretValidation.valid && secretValidation.error) {
      errors.push(secretValidation.error);
    }

    const integrityValid = commitment.verify(recipient, secret).toBoolean();
    if (!integrityValid) {
      errors.push('Commitment integrity check failed');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

// ============================================================================
// COMMITMENT STORE
// ============================================================================

export class CommitmentStore {
  private commitments: Map<string, TransferCommitment>;
  private commitmentsByChain: Map<number, Set<string>>;
  private commitmentsByRecipient: Map<string, Set<string>>;
  private commitmentsByTimestamp: Map<number, Set<string>>;

  constructor() {
    this.commitments = new Map();
    this.commitmentsByChain = new Map();
    this.commitmentsByRecipient = new Map();
    this.commitmentsByTimestamp = new Map();
  }

  add(commitment: TransferCommitment): void {
    const hashStr = commitment.hash.toString();
    
    if (this.commitments.has(hashStr)) {
      throw new Error('Commitment already exists');
    }
    
    this.commitments.set(hashStr, commitment);
    
    const targetChain = Number(commitment.targetChain.value.toString());
    if (!this.commitmentsByChain.has(targetChain)) {
      this.commitmentsByChain.set(targetChain, new Set());
    }
    this.commitmentsByChain.get(targetChain)!.add(hashStr);
    
    const recipientHashStr = commitment.recipientHash.toString();
    if (!this.commitmentsByRecipient.has(recipientHashStr)) {
      this.commitmentsByRecipient.set(recipientHashStr, new Set());
    }
    this.commitmentsByRecipient.get(recipientHashStr)!.add(hashStr);

    const timestampBucket = Math.floor(Number(commitment.timestamp.value.toString()) / 3600);
    if (!this.commitmentsByTimestamp.has(timestampBucket)) {
      this.commitmentsByTimestamp.set(timestampBucket, new Set());
    }
    this.commitmentsByTimestamp.get(timestampBucket)!.add(hashStr);
  }

  get(hash: Field): TransferCommitment | undefined {
    return this.commitments.get(hash.toString());
  }

  has(hash: Field): boolean {
    return this.commitments.has(hash.toString());
  }

  getByChain(chainId: number): TransferCommitment[] {
    const hashes = this.commitmentsByChain.get(chainId);
    if (!hashes) return [];
    
    return Array.from(hashes)
      .map(hash => this.commitments.get(hash))
      .filter((c): c is TransferCommitment => c !== undefined);
  }

  getByRecipient(recipientHash: Field): TransferCommitment[] {
    const hashes = this.commitmentsByRecipient.get(recipientHash.toString());
    if (!hashes) return [];
    
    return Array.from(hashes)
      .map(hash => this.commitments.get(hash))
      .filter((c): c is TransferCommitment => c !== undefined);
  }

  getByTimeRange(startTime: bigint, endTime: bigint): TransferCommitment[] {
    const startBucket = Math.floor(Number(startTime) / 3600);
    const endBucket = Math.floor(Number(endTime) / 3600);
    
    const results: TransferCommitment[] = [];
    
    for (let bucket = startBucket; bucket <= endBucket; bucket++) {
      const hashes = this.commitmentsByTimestamp.get(bucket);
      if (hashes) {
        hashes.forEach(hash => {
          const commitment = this.commitments.get(hash);
          if (commitment) {
            const timestamp = commitment.timestamp.value.toBigInt();
            if (timestamp >= startTime && timestamp <= endTime) {
              results.push(commitment);
            }
          }
        });
      }
    }
    
    return results;
  }

  getAll(): TransferCommitment[] {
    return Array.from(this.commitments.values());
  }

  remove(hash: Field): boolean {
    const hashStr = hash.toString();
    const commitment = this.commitments.get(hashStr);
    
    if (!commitment) return false;
    
    this.commitments.delete(hashStr);
    
    const targetChain = Number(commitment.targetChain.value.toString());
    this.commitmentsByChain.get(targetChain)?.delete(hashStr);
    
    const recipientHashStr = commitment.recipientHash.toString();
    this.commitmentsByRecipient.get(recipientHashStr)?.delete(hashStr);

    const timestampBucket = Math.floor(Number(commitment.timestamp.value.toString()) / 3600);
    this.commitmentsByTimestamp.get(timestampBucket)?.delete(hashStr);
    
    return true;
  }

  clear(): void {
    this.commitments.clear();
    this.commitmentsByChain.clear();
    this.commitmentsByRecipient.clear();
    this.commitmentsByTimestamp.clear();
  }

  size(): number {
    return this.commitments.size;
  }

  exportToJSON(): string {
    const data = Array.from(this.commitments.values()).map(c => c.toJSON());
    return JSON.stringify(data, null, 2);
  }

  importFromJSON(json: string): void {
    const data = JSON.parse(json);
    this.clear();
    
    data.forEach((item: any) => {
      const commitment = TransferCommitment.fromJSON(item);
      this.add(commitment);
    });
  }

  async saveToFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const json = this.exportToJSON();
    await fs.writeFile(filepath, json, 'utf8');
  }

  async loadFromFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const json = await fs.readFile(filepath, 'utf8');
    this.importFromJSON(json);
  }

  pruneExpired(currentTime?: bigint): number {
    const now = currentTime ?? BigInt(Math.floor(Date.now() / 1000));
    let pruned = 0;

    const toRemove: Field[] = [];

    this.commitments.forEach((commitment) => {
      if (commitment.isExpired(UInt64.from(now)).toBoolean()) {
        toRemove.push(commitment.hash);
      }
    });

    toRemove.forEach(hash => {
      if (this.remove(hash)) {
        pruned++;
      }
    });

    return pruned;
  }

  getStatistics(): {
    total: number;
    byChain: Record<number, number>;
    oldestTimestamp: bigint;
    newestTimestamp: bigint;
    totalAmount: bigint;
  } {
    const stats = {
      total: this.commitments.size,
      byChain: {} as Record<number, number>,
      oldestTimestamp: 0n,
      newestTimestamp: 0n,
      totalAmount: 0n,
    };

    if (this.commitments.size === 0) return stats;

    let oldest = BigInt(Number.MAX_SAFE_INTEGER);
    let newest = 0n;

    this.commitments.forEach((commitment) => {
      const chain = Number(commitment.targetChain.value.toString());
      stats.byChain[chain] = (stats.byChain[chain] || 0) + 1;

      const timestamp = commitment.timestamp.value.toBigInt();
      if (timestamp < oldest) oldest = timestamp;
      if (timestamp > newest) newest = timestamp;

      stats.totalAmount += commitment.amount.value.toBigInt();
    });

    stats.oldestTimestamp = oldest;
    stats.newestTimestamp = newest;

    return stats;
  }
}

// ============================================================================
// COMMITMENT UTILITIES
// ============================================================================

export class CommitmentUtils {
  static generateSecret(): Field {
    return Field.random();
  }

  static generateNonce(): Field {
    return Field.random();
  }

  static hashRecipient(recipient: Field, secret: Field): Field {
    return Poseidon.hash([recipient, secret]);
  }

  static recipientFromPublicKey(publicKey: PublicKey): Field {
    return Poseidon.hash([publicKey.x, publicKey.y]);
  }

  static getCurrentTimestamp(): UInt64 {
    return UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
  }

  static createQuickCommitment(
    amount: bigint,
    recipientPublicKey: PublicKey,
    sourceChain: number,
    targetChain: number
  ): { commitment: TransferCommitment; secret: Field; nonce: Field } {
    const secret = this.generateSecret();
    const nonce = this.generateNonce();
    const recipient = this.recipientFromPublicKey(recipientPublicKey);
    const timestamp = this.getCurrentTimestamp();
    
    const commitment = TransferCommitment.create(
      UInt64.from(amount),
      recipient,
      secret,
      UInt32.from(sourceChain),
      UInt32.from(targetChain),
      timestamp,
      nonce
    );
    
    return { commitment, secret, nonce };
  }

  static verifyCommitmentIntegrity(
    commitment: TransferCommitment,
    recipient: Field,
    secret: Field
  ): boolean {
    return commitment.verify(recipient, secret).toBoolean();
  }

  static isCommitmentExpired(
    commitment: TransferCommitment,
    currentTime?: bigint
  ): boolean {
    const now = currentTime ?? BigInt(Math.floor(Date.now() / 1000));
    return commitment.isExpired(UInt64.from(now)).toBoolean();
  }

  static sortByTimestamp(commitments: TransferCommitment[]): TransferCommitment[] {
    return commitments.sort((a, b) => 
      Number(a.timestamp.value.sub(b.timestamp.value).toString())
    );
  }

  static sortByAmount(commitments: TransferCommitment[]): TransferCommitment[] {
    return commitments.sort((a, b) => 
      Number(a.amount.value.sub(b.amount.value).toString())
    );
  }

  static filterExpired(
    commitments: TransferCommitment[],
    currentTime?: bigint
  ): TransferCommitment[] {
    const now = currentTime ?? BigInt(Math.floor(Date.now() / 1000));
    return commitments.filter(c => !this.isCommitmentExpired(c, now));
  }

  static filterByChain(
    commitments: TransferCommitment[],
    targetChain: number
  ): TransferCommitment[] {
    return commitments.filter(c => 
      Number(c.targetChain.value.toString()) === targetChain
    );
  }

  static filterByAmountRange(
    commitments: TransferCommitment[],
    minAmount: bigint,
    maxAmount: bigint
  ): TransferCommitment[] {
    return commitments.filter(c => {
      const amount = c.amount.value.toBigInt();
      return amount >= minAmount && amount <= maxAmount;
    });
  }

  static getTotalAmount(commitments: TransferCommitment[]): bigint {
    return commitments.reduce((sum, c) => sum + c.amount.value.toBigInt(), 0n);
  }

  static groupByChain(
    commitments: TransferCommitment[]
  ): Map<number, TransferCommitment[]> {
    const groups = new Map<number, TransferCommitment[]>();
    
    commitments.forEach(c => {
      const chain = Number(c.targetChain.value.toString());
      if (!groups.has(chain)) {
        groups.set(chain, []);
      }
      groups.get(chain)!.push(c);
    });
    
    return groups;
  }

  static groupByRecipient(
    commitments: TransferCommitment[]
  ): Map<string, TransferCommitment[]> {
    const groups = new Map<string, TransferCommitment[]>();
    
    commitments.forEach(c => {
      const recipient = c.recipientHash.toString();
      if (!groups.has(recipient)) {
        groups.set(recipient, []);
      }
      groups.get(recipient)!.push(c);
    });
    
    return groups;
  }
}