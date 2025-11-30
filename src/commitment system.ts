// ============================================================================
// COMMITMENT SYSTEM - FULL IMPLEMENTATION
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
    const EXPIRY_SECONDS = UInt64.from(86400); // 24 hours
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

  setAmount(amount: bigint | UInt64): CommitmentBuilder {
    this.amount = amount instanceof UInt64 ? amount : UInt64.from(amount);
    return this;
  }

  setRecipient(recipient: Field | string | bigint): CommitmentBuilder {
    if (recipient instanceof Field) {
      this.recipient = recipient;
    } else if (typeof recipient === 'string') {
      this.recipient = Field.from(BigInt(recipient));
    } else {
      this.recipient = Field.from(recipient);
    }
    return this;
  }

  setSecret(secret: Field | string | bigint): CommitmentBuilder {
    if (secret instanceof Field) {
      this.secret = secret;
    } else if (typeof secret === 'string') {
      this.secret = Field.from(BigInt(secret));
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

  setTimestamp(timestamp: bigint | UInt64): CommitmentBuilder {
    this.timestamp = timestamp instanceof UInt64 ? timestamp : UInt64.from(timestamp);
    return this;
  }

  setNonce(nonce: Field | string | bigint): CommitmentBuilder {
    if (nonce instanceof Field) {
      this.nonce = nonce;
    } else if (typeof nonce === 'string') {
      this.nonce = Field.from(BigInt(nonce));
    } else {
      this.nonce = Field.from(nonce);
    }
    return this;
  }

  build(): TransferCommitment {
    if (!this.amount || !this.recipient || !this.secret || 
        !this.sourceChain || !this.targetChain || !this.timestamp || !this.nonce) {
      throw new Error('All commitment fields must be set before building');
    }

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
}

// ============================================================================
// COMMITMENT VALIDATOR
// ============================================================================

export class CommitmentValidator {
  static MIN_AMOUNT = 1n;
  static MAX_AMOUNT = 1_000_000_000_000_000n; // 1M MINA
  static MAX_AGE_SECONDS = 86400n; // 24 hours

  static validateAmount(amount: UInt64): { valid: boolean; error?: string } {
    const value = amount.value.toBigInt();
    
    if (value < this.MIN_AMOUNT) {
      return { valid: false, error: 'Amount below minimum' };
    }
    
    if (value > this.MAX_AMOUNT) {
      return { valid: false, error: 'Amount exceeds maximum' };
    }
    
    return { valid: true };
  }

  static validateChains(
    sourceChain: UInt32,
    targetChain: UInt32
  ): { valid: boolean; error?: string } {
    if (sourceChain.value.equals(targetChain.value).toBoolean()) {
      return { valid: false, error: 'Source and target chains must differ' };
    }
    
    const SUPPORTED_CHAINS = [1, 137, 42161, 10, 43114, 56, 8453, 324, 534352];
    const sourceSupported = SUPPORTED_CHAINS.includes(Number(sourceChain.value.toString()));
    const targetSupported = SUPPORTED_CHAINS.includes(Number(targetChain.value.toString()));
    
    if (!sourceSupported) {
      return { valid: false, error: 'Source chain not supported' };
    }
    
    if (!targetSupported) {
      return { valid: false, error: 'Target chain not supported' };
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
      return { valid: false, error: 'Commitment expired' };
    }
    
    return { valid: true };
  }

  static validateCommitment(
    commitment: TransferCommitment,
    currentTime: bigint
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    const amountValidation = this.validateAmount(commitment.amount);
    if (!amountValidation.valid && amountValidation.error) {
      errors.push(amountValidation.error);
    }
    
    const chainValidation = this.validateChains(commitment.sourceChain, commitment.targetChain);
    if (!chainValidation.valid && chainValidation.error) {
      errors.push(chainValidation.error);
    }
    
    const timestampValidation = this.validateTimestamp(commitment.timestamp, currentTime);
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
// COMMITMENT STORE
// ============================================================================

export class CommitmentStore {
  private commitments: Map<string, TransferCommitment>;
  private commitmentsByChain: Map<number, Set<string>>;
  private commitmentsByRecipient: Map<string, Set<string>>;

  constructor() {
    this.commitments = new Map();
    this.commitmentsByChain = new Map();
    this.commitmentsByRecipient = new Map();
  }

  add(commitment: TransferCommitment): void {
    const hashStr = commitment.hash.toString();
    
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
    
    return true;
  }

  clear(): void {
    this.commitments.clear();
    this.commitmentsByChain.clear();
    this.commitmentsByRecipient.clear();
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

  static compareCommitments(a: TransferCommitment, b: TransferCommitment): number {
    return Number(a.timestamp.value.sub(b.timestamp.value).toString());
  }

  static sortCommitmentsByTimestamp(
    commitments: TransferCommitment[]
  ): TransferCommitment[] {
    return commitments.sort(this.compareCommitments);
  }

  static filterExpiredCommitments(
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
}