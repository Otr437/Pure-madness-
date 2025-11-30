// ============================================================================
// X402 NULLIFIER SYSTEM - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 5 of 8
// Full nullifier creation, verification, double-spend prevention
// Storage, validation, caching, and pruning
// ============================================================================

import {
  Field,
  Poseidon,
  Bool,
  UInt64,
  Struct,
} from 'o1js';

// ============================================================================
// TRANSFER NULLIFIER STRUCTURE
// ============================================================================

export class TransferNullifier extends Struct({
  hash: Field,
  commitmentHash: Field,
  timestamp: UInt64,
}) {
  static create(
    secret: Field,
    commitmentHash: Field,
    timestamp: UInt64
  ): TransferNullifier {
    const hash = Poseidon.hash([secret, commitmentHash, timestamp.value]);
    return new TransferNullifier({ hash, commitmentHash, timestamp });
  }

  verify(secret: Field): Bool {
    const recomputedHash = Poseidon.hash([
      secret,
      this.commitmentHash,
      this.timestamp.value,
    ]);
    return this.hash.equals(recomputedHash);
  }

  toJSON(): {
    hash: string;
    commitmentHash: string;
    timestamp: string;
  } {
    return {
      hash: this.hash.toString(),
      commitmentHash: this.commitmentHash.toString(),
      timestamp: this.timestamp.toString(),
    };
  }

  static fromJSON(json: {
    hash: string;
    commitmentHash: string;
    timestamp: string;
  }): TransferNullifier {
    return new TransferNullifier({
      hash: Field.from(json.hash),
      commitmentHash: Field.from(json.commitmentHash),
      timestamp: UInt64.from(json.timestamp),
    });
  }

  equals(other: TransferNullifier): boolean {
    return this.hash.equals(other.hash).toBoolean();
  }

  toString(): string {
    return JSON.stringify(this.toJSON(), null, 2);
  }
}

// ============================================================================
// NULLIFIER BUILDER
// ============================================================================

export class NullifierBuilder {
  private secret?: Field;
  private commitmentHash?: Field;
  private timestamp?: UInt64;

  setSecret(secret: Field | string | bigint): NullifierBuilder {
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

  setCommitmentHash(hash: Field | string | bigint): NullifierBuilder {
    if (hash instanceof Field) {
      this.commitmentHash = hash;
    } else if (typeof hash === 'string') {
      const clean = hash.startsWith('0x') ? hash.slice(2) : hash;
      this.commitmentHash = Field.from(BigInt('0x' + clean));
    } else {
      this.commitmentHash = Field.from(hash);
    }
    return this;
  }

  setTimestamp(timestamp: bigint | UInt64 | number): NullifierBuilder {
    if (timestamp instanceof UInt64) {
      this.timestamp = timestamp;
    } else if (typeof timestamp === 'number') {
      this.timestamp = UInt64.from(BigInt(timestamp));
    } else {
      this.timestamp = UInt64.from(timestamp);
    }
    return this;
  }

  useCurrentTimestamp(): NullifierBuilder {
    this.timestamp = UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
    return this;
  }

  build(): TransferNullifier {
    if (!this.secret) throw new Error('Secret not set');
    if (!this.commitmentHash) throw new Error('Commitment hash not set');
    if (!this.timestamp) throw new Error('Timestamp not set');

    return TransferNullifier.create(this.secret, this.commitmentHash, this.timestamp);
  }

  buildWithCurrentTime(): TransferNullifier {
    if (!this.timestamp) this.useCurrentTimestamp();
    return this.build();
  }

  reset(): NullifierBuilder {
    this.secret = undefined;
    this.commitmentHash = undefined;
    this.timestamp = undefined;
    return this;
  }
}

// ============================================================================
// NULLIFIER STORE
// ============================================================================

export class NullifierStore {
  private nullifiers: Map<string, TransferNullifier>;
  private nullifiersByCommitment: Map<string, string>;
  private nullifiersByTimestamp: Map<number, Set<string>>;
  private nullifiersByHour: Map<number, Set<string>>;

  constructor() {
    this.nullifiers = new Map();
    this.nullifiersByCommitment = new Map();
    this.nullifiersByTimestamp = new Map();
    this.nullifiersByHour = new Map();
  }

  add(nullifier: TransferNullifier): void {
    const hashStr = nullifier.hash.toString();
    
    if (this.nullifiers.has(hashStr)) {
      throw new Error('Nullifier already exists - DOUBLE SPEND DETECTED');
    }
    
    const commitmentHashStr = nullifier.commitmentHash.toString();
    if (this.nullifiersByCommitment.has(commitmentHashStr)) {
      throw new Error('Commitment already spent - DOUBLE SPEND DETECTED');
    }

    this.nullifiers.set(hashStr, nullifier);
    this.nullifiersByCommitment.set(commitmentHashStr, hashStr);
    
    const timestampValue = Number(nullifier.timestamp.value.toString());
    const timestampBucket = Math.floor(timestampValue / 3600);
    if (!this.nullifiersByTimestamp.has(timestampBucket)) {
      this.nullifiersByTimestamp.set(timestampBucket, new Set());
    }
    this.nullifiersByTimestamp.get(timestampBucket)!.add(hashStr);

    const hourBucket = Math.floor(timestampValue / 3600);
    if (!this.nullifiersByHour.has(hourBucket)) {
      this.nullifiersByHour.set(hourBucket, new Set());
    }
    this.nullifiersByHour.get(hourBucket)!.add(hashStr);
  }

  has(hash: Field): boolean {
    return this.nullifiers.has(hash.toString());
  }

  hasCommitment(commitmentHash: Field): boolean {
    return this.nullifiersByCommitment.has(commitmentHash.toString());
  }

  get(hash: Field): TransferNullifier | undefined {
    return this.nullifiers.get(hash.toString());
  }

  getByCommitment(commitmentHash: Field): TransferNullifier | undefined {
    const nullifierHash = this.nullifiersByCommitment.get(commitmentHash.toString());
    if (!nullifierHash) return undefined;
    return this.nullifiers.get(nullifierHash);
  }

  getByTimeRange(startTime: bigint, endTime: bigint): TransferNullifier[] {
    const startBucket = Math.floor(Number(startTime) / 3600);
    const endBucket = Math.floor(Number(endTime) / 3600);
    
    const results: TransferNullifier[] = [];
    
    for (let bucket = startBucket; bucket <= endBucket; bucket++) {
      const hashes = this.nullifiersByTimestamp.get(bucket);
      if (hashes) {
        hashes.forEach(hash => {
          const nullifier = this.nullifiers.get(hash);
          if (nullifier) {
            const timestamp = nullifier.timestamp.value.toBigInt();
            if (timestamp >= startTime && timestamp <= endTime) {
              results.push(nullifier);
            }
          }
        });
      }
    }
    
    return results;
  }

  getByHour(hourBucket: number): TransferNullifier[] {
    const hashes = this.nullifiersByHour.get(hourBucket);
    if (!hashes) return [];

    return Array.from(hashes)
      .map(hash => this.nullifiers.get(hash))
      .filter((n): n is TransferNullifier => n !== undefined);
  }

  getAll(): TransferNullifier[] {
    return Array.from(this.nullifiers.values());
  }

  size(): number {
    return this.nullifiers.size;
  }

  clear(): void {
    this.nullifiers.clear();
    this.nullifiersByCommitment.clear();
    this.nullifiersByTimestamp.clear();
    this.nullifiersByHour.clear();
  }

  remove(hash: Field): boolean {
    const hashStr = hash.toString();
    const nullifier = this.nullifiers.get(hashStr);
    
    if (!nullifier) return false;
    
    this.nullifiers.delete(hashStr);
    
    const commitmentHashStr = nullifier.commitmentHash.toString();
    this.nullifiersByCommitment.delete(commitmentHashStr);
    
    const timestampBucket = Math.floor(Number(nullifier.timestamp.value.toString()) / 3600);
    this.nullifiersByTimestamp.get(timestampBucket)?.delete(hashStr);

    const hourBucket = Math.floor(Number(nullifier.timestamp.value.toString()) / 3600);
    this.nullifiersByHour.get(hourBucket)?.delete(hashStr);
    
    return true;
  }

  exportToJSON(): string {
    const data = Array.from(this.nullifiers.values()).map(n => n.toJSON());
    return JSON.stringify(data, null, 2);
  }

  importFromJSON(json: string): void {
    const data = JSON.parse(json);
    this.clear();
    
    data.forEach((item: any) => {
      const nullifier = TransferNullifier.fromJSON(item);
      try {
        this.add(nullifier);
      } catch (error) {
        console.warn(`Skipping duplicate nullifier: ${error}`);
      }
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

  pruneOldNullifiers(cutoffTime: bigint): number {
    const cutoffBucket = Math.floor(Number(cutoffTime) / 3600);
    let pruned = 0;
    
    const bucketsToDelete: number[] = [];
    
    this.nullifiersByTimestamp.forEach((hashes, bucket) => {
      if (bucket < cutoffBucket) {
        hashes.forEach(hash => {
          const nullifier = this.nullifiers.get(hash);
          if (nullifier && nullifier.timestamp.value.toBigInt() < cutoffTime) {
            this.nullifiers.delete(hash);
            this.nullifiersByCommitment.delete(nullifier.commitmentHash.toString());
            pruned++;
          }
        });
        bucketsToDelete.push(bucket);
      }
    });
    
    bucketsToDelete.forEach(bucket => {
      this.nullifiersByTimestamp.delete(bucket);
      this.nullifiersByHour.delete(bucket);
    });
    
    return pruned;
  }

  getStatistics(): {
    total: number;
    oldestTimestamp: bigint;
    newestTimestamp: bigint;
    uniqueCommitments: number;
    averagePerHour: number;
  } {
    const stats = {
      total: this.nullifiers.size,
      oldestTimestamp: 0n,
      newestTimestamp: 0n,
      uniqueCommitments: this.nullifiersByCommitment.size,
      averagePerHour: 0,
    };

    if (this.nullifiers.size === 0) return stats;

    let oldest = BigInt(Number.MAX_SAFE_INTEGER);
    let newest = 0n;

    this.nullifiers.forEach((nullifier) => {
      const timestamp = nullifier.timestamp.value.toBigInt();
      if (timestamp < oldest) oldest = timestamp;
      if (timestamp > newest) newest = timestamp;
    });

    stats.oldestTimestamp = oldest;
    stats.newestTimestamp = newest;

    const timeRangeHours = Number(newest - oldest) / 3600;
    if (timeRangeHours > 0) {
      stats.averagePerHour = this.nullifiers.size / timeRangeHours;
    }

    return stats;
  }

  detectDoubleSpends(): Array<{
    commitmentHash: string;
    nullifiers: TransferNullifier[];
    count: number;
  }> {
    const byCommitment = new Map<string, TransferNullifier[]>();
    
    this.nullifiers.forEach((nullifier) => {
      const key = nullifier.commitmentHash.toString();
      if (!byCommitment.has(key)) {
        byCommitment.set(key, []);
      }
      byCommitment.get(key)!.push(nullifier);
    });
    
    const doubleSpends: Array<{
      commitmentHash: string;
      nullifiers: TransferNullifier[];
      count: number;
    }> = [];
    
    byCommitment.forEach((nullifiers, commitmentHash) => {
      if (nullifiers.length > 1) {
        doubleSpends.push({
          commitmentHash,
          nullifiers,
          count: nullifiers.length,
        });
      }
    });
    
    return doubleSpends;
  }
}

// ============================================================================
// NULLIFIER VALIDATOR
// ============================================================================

export class NullifierValidator {
  static MAX_AGE_SECONDS = 86400n;

  static validateNullifier(
    nullifier: TransferNullifier,
    secret: Field
  ): { valid: boolean; error?: string } {
    const isValid = nullifier.verify(secret).toBoolean();
    
    if (!isValid) {
      return { valid: false, error: 'Nullifier verification failed - secret mismatch' };
    }
    
    return { valid: true };
  }

  static validateNotSpent(
    nullifier: TransferNullifier,
    store: NullifierStore
  ): { valid: boolean; error?: string } {
    if (store.has(nullifier.hash)) {
      return { valid: false, error: 'Nullifier already spent - DOUBLE SPEND ATTEMPT' };
    }
    
    if (store.hasCommitment(nullifier.commitmentHash)) {
      return { valid: false, error: 'Commitment already spent - DOUBLE SPEND ATTEMPT' };
    }
    
    return { valid: true };
  }

  static validateTimestamp(
    nullifier: TransferNullifier,
    currentTime: bigint
  ): { valid: boolean; error?: string } {
    const timestampValue = nullifier.timestamp.value.toBigInt();
    
    if (timestampValue > currentTime) {
      return { valid: false, error: 'Nullifier timestamp in future' };
    }
    
    const age = currentTime - timestampValue;
    if (age > this.MAX_AGE_SECONDS) {
      return { valid: false, error: `Nullifier too old (age: ${age}s, max: ${this.MAX_AGE_SECONDS}s)` };
    }
    
    return { valid: true };
  }

  static validateCommitmentHash(commitmentHash: Field): { valid: boolean; error?: string } {
    const value = commitmentHash.toBigInt();
    
    if (value === 0n) {
      return { valid: false, error: 'Commitment hash cannot be zero' };
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

  static validateComplete(
    nullifier: TransferNullifier,
    secret: Field,
    store: NullifierStore,
    currentTime: bigint
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    const secretValidation = this.validateSecret(secret);
    if (!secretValidation.valid && secretValidation.error) {
      errors.push(secretValidation.error);
    }

    const commitmentValidation = this.validateCommitmentHash(nullifier.commitmentHash);
    if (!commitmentValidation.valid && commitmentValidation.error) {
      errors.push(commitmentValidation.error);
    }

    const nullifierValidation = this.validateNullifier(nullifier, secret);
    if (!nullifierValidation.valid && nullifierValidation.error) {
      errors.push(nullifierValidation.error);
    }
    
    const spentValidation = this.validateNotSpent(nullifier, store);
    if (!spentValidation.valid && spentValidation.error) {
      errors.push(spentValidation.error);
    }
    
    const timestampValidation = this.validateTimestamp(nullifier, currentTime);
    if (!timestampValidation.valid && timestampValidation.error) {
      errors.push(timestampValidation.error);
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

// ============================================================================
// NULLIFIER UTILITIES
// ============================================================================

export class NullifierUtils {
  static createFromCommitment(
    commitmentHash: Field,
    secret: Field,
    timestamp?: bigint
  ): TransferNullifier {
    const ts = timestamp ?? BigInt(Math.floor(Date.now() / 1000));
    return TransferNullifier.create(secret, commitmentHash, UInt64.from(ts));
  }

  static verifyNullifierIntegrity(
    nullifier: TransferNullifier,
    secret: Field
  ): boolean {
    return nullifier.verify(secret).toBoolean();
  }

  static sortByTimestamp(nullifiers: TransferNullifier[]): TransferNullifier[] {
    return nullifiers.sort((a, b) => 
      Number(a.timestamp.value.sub(b.timestamp.value).toString())
    );
  }

  static filterByTimeRange(
    nullifiers: TransferNullifier[],
    startTime: bigint,
    endTime: bigint
  ): TransferNullifier[] {
    return nullifiers.filter(n => {
      const timestamp = n.timestamp.value.toBigInt();
      return timestamp >= startTime && timestamp <= endTime;
    });
  }

  static filterByCommitments(
    nullifiers: TransferNullifier[],
    commitmentHashes: Set<string>
  ): TransferNullifier[] {
    return nullifiers.filter(n => 
      commitmentHashes.has(n.commitmentHash.toString())
    );
  }

  static groupByHour(
    nullifiers: TransferNullifier[]
  ): Map<number, TransferNullifier[]> {
    const groups = new Map<number, TransferNullifier[]>();
    
    nullifiers.forEach(n => {
      const hour = Math.floor(Number(n.timestamp.value.toString()) / 3600);
      if (!groups.has(hour)) {
        groups.set(hour, []);
      }
      groups.get(hour)!.push(n);
    });
    
    return groups;
  }

  static groupByDay(
    nullifiers: TransferNullifier[]
  ): Map<number, TransferNullifier[]> {
    const groups = new Map<number, TransferNullifier[]>();
    
    nullifiers.forEach(n => {
      const day = Math.floor(Number(n.timestamp.value.toString()) / 86400);
      if (!groups.has(day)) {
        groups.set(day, []);
      }
      groups.get(day)!.push(n);
    });
    
    return groups;
  }

  static groupByCommitment(
    nullifiers: TransferNullifier[]
  ): Map<string, TransferNullifier[]> {
    const groups = new Map<string, TransferNullifier[]>();
    
    nullifiers.forEach(n => {
      const key = n.commitmentHash.toString();
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(n);
    });
    
    return groups;
  }

  static detectDoubleSpendAttempts(
    nullifiers: TransferNullifier[]
  ): Array<{ commitmentHash: string; nullifiers: TransferNullifier[] }> {
    const byCommitment = new Map<string, TransferNullifier[]>();
    
    nullifiers.forEach(n => {
      const key = n.commitmentHash.toString();
      if (!byCommitment.has(key)) {
        byCommitment.set(key, []);
      }
      byCommitment.get(key)!.push(n);
    });
    
    const doubleSpends: Array<{ commitmentHash: string; nullifiers: TransferNullifier[] }> = [];
    
    byCommitment.forEach((nulls, commitmentHash) => {
      if (nulls.length > 1) {
        doubleSpends.push({ commitmentHash, nullifiers: nulls });
      }
    });
    
    return doubleSpends;
  }

  static getStatistics(nullifiers: TransferNullifier[]): {
    total: number;
    oldestTimestamp: bigint;
    newestTimestamp: bigint;
    uniqueCommitments: number;
    nullifiersPerHour: number;
    doubleSpendAttempts: number;
  } {
    if (nullifiers.length === 0) {
      return {
        total: 0,
        oldestTimestamp: 0n,
        newestTimestamp: 0n,
        uniqueCommitments: 0,
        nullifiersPerHour: 0,
        doubleSpendAttempts: 0,
      };
    }
    
    const sorted = this.sortByTimestamp(nullifiers);
    const oldest = sorted[0].timestamp.value.toBigInt();
    const newest = sorted[sorted.length - 1].timestamp.value.toBigInt();
    
    const uniqueCommitments = new Set(
      nullifiers.map(n => n.commitmentHash.toString())
    ).size;
    
    const timeRange = Number(newest - oldest) / 3600;
    const nullifiersPerHour = timeRange > 0 ? nullifiers.length / timeRange : 0;

    const doubleSpends = this.detectDoubleSpendAttempts(nullifiers);
    
    return {
      total: nullifiers.length,
      oldestTimestamp: oldest,
      newestTimestamp: newest,
      uniqueCommitments,
      nullifiersPerHour,
      doubleSpendAttempts: doubleSpends.length,
    };
  }
}

// ============================================================================
// NULLIFIER CACHE
// ============================================================================

export class NullifierCache {
  private cache: Map<string, boolean>;
  private maxSize: number;
  private accessOrder: string[];
  private hits: number;
  private misses: number;

  constructor(maxSize: number = 10000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.accessOrder = [];
    this.hits = 0;
    this.misses = 0;
  }

  has(nullifierHash: Field): boolean | null {
    const key = nullifierHash.toString();
    
    if (!this.cache.has(key)) {
      this.misses++;
      return null;
    }
    
    this.hits++;
    
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
      this.accessOrder.push(key);
    }
    
    return this.cache.get(key)!;
  }

  set(nullifierHash: Field, spent: boolean): void {
    const key = nullifierHash.toString();
    
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const lru = this.accessOrder.shift();
      if (lru) {
        this.cache.delete(lru);
      }
    }
    
    this.cache.set(key, spent);
    
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
    }
    this.accessOrder.push(key);
  }

  delete(nullifierHash: Field): boolean {
    const key = nullifierHash.toString();
    
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
    }
    
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
    this.accessOrder = [];
    this.hits = 0;
    this.misses = 0;
  }

  size(): number {
    return this.cache.size;
  }

  getHitRate(): number {
    const total = this.hits + this.misses;
    return total === 0 ? 0 : this.hits / total;
  }

  getStatistics(): {
    size: number;
    maxSize: number;
    hits: number;
    misses: number;
    hitRate: number;
    utilization: number;
  } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      hits: this.hits,
      misses: this.misses,
      hitRate: this.getHitRate(),
      utilization: (this.cache.size / this.maxSize) * 100,
    };
  }

  resetStatistics(): void {
    this.hits = 0;
    this.misses = 0;
  }
}