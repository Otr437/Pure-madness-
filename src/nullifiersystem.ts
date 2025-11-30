// ============================================================================
// NULLIFIER SYSTEM - FULL IMPLEMENTATION
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

    return new TransferNullifier({
      hash,
      commitmentHash,
      timestamp,
    });
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
      this.secret = Field.from(BigInt(secret));
    } else {
      this.secret = Field.from(secret);
    }
    return this;
  }

  setCommitmentHash(hash: Field | string | bigint): NullifierBuilder {
    if (hash instanceof Field) {
      this.commitmentHash = hash;
    } else if (typeof hash === 'string') {
      this.commitmentHash = Field.from(BigInt(hash));
    } else {
      this.commitmentHash = Field.from(hash);
    }
    return this;
  }

  setTimestamp(timestamp: bigint | UInt64): NullifierBuilder {
    this.timestamp = timestamp instanceof UInt64 ? timestamp : UInt64.from(timestamp);
    return this;
  }

  build(): TransferNullifier {
    if (!this.secret || !this.commitmentHash || !this.timestamp) {
      throw new Error('All nullifier fields must be set before building');
    }

    return TransferNullifier.create(
      this.secret,
      this.commitmentHash,
      this.timestamp
    );
  }
}

// ============================================================================
// NULLIFIER STORE
// ============================================================================

export class NullifierStore {
  private nullifiers: Map<string, TransferNullifier>;
  private nullifiersByCommitment: Map<string, string>;
  private nullifiersByTimestamp: Map<number, Set<string>>;

  constructor() {
    this.nullifiers = new Map();
    this.nullifiersByCommitment = new Map();
    this.nullifiersByTimestamp = new Map();
  }

  add(nullifier: TransferNullifier): void {
    const hashStr = nullifier.hash.toString();
    
    if (this.nullifiers.has(hashStr)) {
      throw new Error('Nullifier already exists (double-spend attempt)');
    }
    
    this.nullifiers.set(hashStr, nullifier);
    
    const commitmentHashStr = nullifier.commitmentHash.toString();
    if (this.nullifiersByCommitment.has(commitmentHashStr)) {
      throw new Error('Commitment already spent');
    }
    this.nullifiersByCommitment.set(commitmentHashStr, hashStr);
    
    const timestampBucket = Math.floor(Number(nullifier.timestamp.value.toString()) / 3600);
    if (!this.nullifiersByTimestamp.has(timestampBucket)) {
      this.nullifiersByTimestamp.set(timestampBucket, new Set());
    }
    this.nullifiersByTimestamp.get(timestampBucket)!.add(hashStr);
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
      this.add(nullifier);
    });
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
    
    bucketsToDelete.forEach(bucket => this.nullifiersByTimestamp.delete(bucket));
    
    return pruned;
  }
}

// ============================================================================
// NULLIFIER VALIDATOR
// ============================================================================

export class NullifierValidator {
  static validateNullifier(
    nullifier: TransferNullifier,
    secret: Field
  ): { valid: boolean; error?: string } {
    const isValid = nullifier.verify(secret).toBoolean();
    
    if (!isValid) {
      return { valid: false, error: 'Nullifier verification failed' };
    }
    
    return { valid: true };
  }

  static validateNotSpent(
    nullifier: TransferNullifier,
    store: NullifierStore
  ): { valid: boolean; error?: string } {
    if (store.has(nullifier.hash)) {
      return { valid: false, error: 'Nullifier already spent' };
    }
    
    if (store.hasCommitment(nullifier.commitmentHash)) {
      return { valid: false, error: 'Commitment already spent' };
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
    
    const MAX_AGE_SECONDS = 86400n; // 24 hours
    const age = currentTime - timestampValue;
    if (age > MAX_AGE_SECONDS) {
      return { valid: false, error: 'Nullifier too old' };
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

  static compareNullifiers(a: TransferNullifier, b: TransferNullifier): number {
    return Number(a.timestamp.value.sub(b.timestamp.value).toString());
  }

  static sortNullifiersByTimestamp(
    nullifiers: TransferNullifier[]
  ): TransferNullifier[] {
    return nullifiers.sort(this.compareNullifiers);
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
  } {
    if (nullifiers.length === 0) {
      return {
        total: 0,
        oldestTimestamp: 0n,
        newestTimestamp: 0n,
        uniqueCommitments: 0,
        nullifiersPerHour: 0,
      };
    }
    
    const sorted = this.sortNullifiersByTimestamp(nullifiers);
    const oldest = sorted[0].timestamp.value.toBigInt();
    const newest = sorted[sorted.length - 1].timestamp.value.toBigInt();
    
    const uniqueCommitments = new Set(
      nullifiers.map(n => n.commitmentHash.toString())
    ).size;
    
    const timeRange = Number(newest - oldest) / 3600;
    const nullifiersPerHour = timeRange > 0 ? nullifiers.length / timeRange : 0;
    
    return {
      total: nullifiers.length,
      oldestTimestamp: oldest,
      newestTimestamp: newest,
      uniqueCommitments,
      nullifiersPerHour,
    };
  }
}

// ============================================================================
// NULLIFIER CACHE (FOR PERFORMANCE)
// ============================================================================

export class NullifierCache {
  private cache: Map<string, boolean>;
  private maxSize: number;
  private accessOrder: string[];

  constructor(maxSize: number = 10000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.accessOrder = [];
  }

  has(nullifierHash: Field): boolean | null {
    const key = nullifierHash.toString();
    
    if (!this.cache.has(key)) {
      return null; // Cache miss
    }
    
    // Move to end (most recently used)
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
      // Evict least recently used
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

  clear(): void {
    this.cache.clear();
    this.accessOrder = [];
  }

  size(): number {
    return this.cache.size;
  }

  getHitRate(): number {
    // Would track hits/misses in production
    return 0;
  }
}