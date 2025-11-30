// ============================================================================
// MERKLE TREE MANAGER - FULL IMPLEMENTATION
// ============================================================================

import {
  Field,
  Poseidon,
  MerkleTree,
  MerkleWitness,
  Bool,
  Struct,
} from 'o1js';

// ============================================================================
// MERKLE WITNESS CLASSES
// ============================================================================

export class CommitmentMerkleWitness extends MerkleWitness(32) {}
export class NullifierMerkleWitness extends MerkleWitness(32) {}

// ============================================================================
// MERKLE TREE MANAGER
// ============================================================================

export class MerkleTreeManager {
  private commitmentTree: MerkleTree;
  private nullifierTree: MerkleTree;
  private commitmentLeaves: Map<string, number>;
  private nullifierLeaves: Map<string, number>;
  private nextCommitmentIndex: number;
  private nextNullifierIndex: number;

  constructor(height: number = 32) {
    this.commitmentTree = new MerkleTree(height);
    this.nullifierTree = new MerkleTree(height);
    this.commitmentLeaves = new Map();
    this.nullifierLeaves = new Map();
    this.nextCommitmentIndex = 0;
    this.nextNullifierIndex = 0;
  }

  // COMMITMENT TREE OPERATIONS

  addCommitment(commitmentHash: Field): {
    index: number;
    witness: CommitmentMerkleWitness;
    oldRoot: Field;
    newRoot: Field;
  } {
    const index = this.nextCommitmentIndex;
    const oldRoot = this.commitmentTree.getRoot();
    
    const witness = new CommitmentMerkleWitness(
      this.commitmentTree.getWitness(BigInt(index))
    );
    
    this.commitmentTree.setLeaf(BigInt(index), commitmentHash);
    
    const newRoot = this.commitmentTree.getRoot();
    
    this.commitmentLeaves.set(commitmentHash.toString(), index);
    this.nextCommitmentIndex++;
    
    return { index, witness, oldRoot, newRoot };
  }

  getCommitmentWitness(commitmentHash: Field): CommitmentMerkleWitness | null {
    const index = this.commitmentLeaves.get(commitmentHash.toString());
    if (index === undefined) {
      return null;
    }
    
    return new CommitmentMerkleWitness(
      this.commitmentTree.getWitness(BigInt(index))
    );
  }

  getCommitmentRoot(): Field {
    return this.commitmentTree.getRoot();
  }

  hasCommitment(commitmentHash: Field): boolean {
    return this.commitmentLeaves.has(commitmentHash.toString());
  }

  getCommitmentIndex(commitmentHash: Field): number | null {
    const index = this.commitmentLeaves.get(commitmentHash.toString());
    return index !== undefined ? index : null;
  }

  getAllCommitments(): Array<{ hash: Field; index: number }> {
    const commitments: Array<{ hash: Field; index: number }> = [];
    
    this.commitmentLeaves.forEach((index, hashStr) => {
      commitments.push({
        hash: Field.from(BigInt(hashStr)),
        index,
      });
    });
    
    return commitments.sort((a, b) => a.index - b.index);
  }

  // NULLIFIER TREE OPERATIONS

  addNullifier(nullifierHash: Field): {
    index: number;
    witness: NullifierMerkleWitness;
    oldRoot: Field;
    newRoot: Field;
  } {
    const index = this.nextNullifierIndex;
    const oldRoot = this.nullifierTree.getRoot();
    
    const witness = new NullifierMerkleWitness(
      this.nullifierTree.getWitness(BigInt(index))
    );
    
    this.nullifierTree.setLeaf(BigInt(index), nullifierHash);
    
    const newRoot = this.nullifierTree.getRoot();
    
    this.nullifierLeaves.set(nullifierHash.toString(), index);
    this.nextNullifierIndex++;
    
    return { index, witness, oldRoot, newRoot };
  }

  getNullifierWitness(nullifierHash: Field): NullifierMerkleWitness | null {
    const index = this.nullifierLeaves.get(nullifierHash.toString());
    if (index === undefined) {
      return null;
    }
    
    return new NullifierMerkleWitness(
      this.nullifierTree.getWitness(BigInt(index))
    );
  }

  getEmptyNullifierWitness(): NullifierMerkleWitness {
    return new NullifierMerkleWitness(
      this.nullifierTree.getWitness(BigInt(this.nextNullifierIndex))
    );
  }

  getNullifierRoot(): Field {
    return this.nullifierTree.getRoot();
  }

  hasNullifier(nullifierHash: Field): boolean {
    return this.nullifierLeaves.has(nullifierHash.toString());
  }

  getNullifierIndex(nullifierHash: Field): number | null {
    const index = this.nullifierLeaves.get(nullifierHash.toString());
    return index !== undefined ? index : null;
  }

  getAllNullifiers(): Array<{ hash: Field; index: number }> {
    const nullifiers: Array<{ hash: Field; index: number }> = [];
    
    this.nullifierLeaves.forEach((index, hashStr) => {
      nullifiers.push({
        hash: Field.from(BigInt(hashStr)),
        index,
      });
    });
    
    return nullifiers.sort((a, b) => a.index - b.index);
  }

  // UTILITY METHODS

  verifyCommitmentMembership(
    commitmentHash: Field,
    witness: CommitmentMerkleWitness,
    root: Field
  ): boolean {
    const calculatedRoot = witness.calculateRoot(commitmentHash);
    return calculatedRoot.equals(root).toBoolean();
  }

  verifyNullifierNonMembership(
    witness: NullifierMerkleWitness,
    root: Field
  ): boolean {
    const calculatedRoot = witness.calculateRoot(Field(0));
    return calculatedRoot.equals(root).toBoolean();
  }

  verifyNullifierMembership(
    nullifierHash: Field,
    witness: NullifierMerkleWitness,
    root: Field
  ): boolean {
    const calculatedRoot = witness.calculateRoot(nullifierHash);
    return calculatedRoot.equals(root).toBoolean();
  }

  // STATISTICS

  getStatistics(): {
    commitmentCount: number;
    nullifierCount: number;
    commitmentRoot: string;
    nullifierRoot: string;
    treeHeight: number;
    maxCapacity: number;
  } {
    const maxCapacity = Math.pow(2, 32);
    
    return {
      commitmentCount: this.nextCommitmentIndex,
      nullifierCount: this.nextNullifierIndex,
      commitmentRoot: this.commitmentTree.getRoot().toString(),
      nullifierRoot: this.nullifierTree.getRoot().toString(),
      treeHeight: 32,
      maxCapacity,
    };
  }

  // SERIALIZATION

  exportState(): {
    commitments: Array<{ hash: string; index: number }>;
    nullifiers: Array<{ hash: string; index: number }>;
    commitmentRoot: string;
    nullifierRoot: string;
    nextCommitmentIndex: number;
    nextNullifierIndex: number;
  } {
    const commitments = Array.from(this.commitmentLeaves.entries()).map(([hash, index]) => ({
      hash,
      index,
    }));
    
    const nullifiers = Array.from(this.nullifierLeaves.entries()).map(([hash, index]) => ({
      hash,
      index,
    }));
    
    return {
      commitments,
      nullifiers,
      commitmentRoot: this.commitmentTree.getRoot().toString(),
      nullifierRoot: this.nullifierTree.getRoot().toString(),
      nextCommitmentIndex: this.nextCommitmentIndex,
      nextNullifierIndex: this.nextNullifierIndex,
    };
  }

  importState(state: {
    commitments: Array<{ hash: string; index: number }>;
    nullifiers: Array<{ hash: string; index: number }>;
    nextCommitmentIndex: number;
    nextNullifierIndex: number;
  }): void {
    this.commitmentLeaves.clear();
    this.nullifierLeaves.clear();
    
    state.commitments.forEach(({ hash, index }) => {
      const hashField = Field.from(BigInt(hash));
      this.commitmentTree.setLeaf(BigInt(index), hashField);
      this.commitmentLeaves.set(hash, index);
    });
    
    state.nullifiers.forEach(({ hash, index }) => {
      const hashField = Field.from(BigInt(hash));
      this.nullifierTree.setLeaf(BigInt(index), hashField);
      this.nullifierLeaves.set(hash, index);
    });
    
    this.nextCommitmentIndex = state.nextCommitmentIndex;
    this.nextNullifierIndex = state.nextNullifierIndex;
  }

  // PERSISTENCE

  async saveToFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const state = this.exportState();
    await fs.writeFile(filepath, JSON.stringify(state, null, 2));
  }

  async loadFromFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const data = await fs.readFile(filepath, 'utf8');
    const state = JSON.parse(data);
    this.importState(state);
  }

  // BATCH OPERATIONS

  addCommitmentBatch(commitmentHashes: Field[]): {
    indices: number[];
    witnesses: CommitmentMerkleWitness[];
    oldRoot: Field;
    newRoot: Field;
  } {
    const oldRoot = this.commitmentTree.getRoot();
    const indices: number[] = [];
    const witnesses: CommitmentMerkleWitness[] = [];
    
    commitmentHashes.forEach(hash => {
      const result = this.addCommitment(hash);
      indices.push(result.index);
      witnesses.push(result.witness);
    });
    
    const newRoot = this.commitmentTree.getRoot();
    
    return { indices, witnesses, oldRoot, newRoot };
  }

  addNullifierBatch(nullifierHashes: Field[]): {
    indices: number[];
    witnesses: NullifierMerkleWitness[];
    oldRoot: Field;
    newRoot: Field;
  } {
    const oldRoot = this.nullifierTree.getRoot();
    const indices: number[] = [];
    const witnesses: NullifierMerkleWitness[] = [];
    
    nullifierHashes.forEach(hash => {
      const result = this.addNullifier(hash);
      indices.push(result.index);
      witnesses.push(result.witness);
    });
    
    const newRoot = this.nullifierTree.getRoot();
    
    return { indices, witnesses, oldRoot, newRoot };
  }

  // VALIDATION

  validateIntegrity(): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    
    // Check commitment indices are sequential
    const commitmentIndices = Array.from(this.commitmentLeaves.values()).sort((a, b) => a - b);
    for (let i = 0; i < commitmentIndices.length; i++) {
      if (commitmentIndices[i] !== i) {
        errors.push(`Commitment index gap at ${i}`);
      }
    }
    
    // Check nullifier indices are sequential
    const nullifierIndices = Array.from(this.nullifierLeaves.values()).sort((a, b) => a - b);
    for (let i = 0; i < nullifierIndices.length; i++) {
      if (nullifierIndices[i] !== i) {
        errors.push(`Nullifier index gap at ${i}`);
      }
    }
    
    // Check next indices match
    if (this.nextCommitmentIndex !== this.commitmentLeaves.size) {
      errors.push(`Commitment count mismatch: ${this.nextCommitmentIndex} vs ${this.commitmentLeaves.size}`);
    }
    
    if (this.nextNullifierIndex !== this.nullifierLeaves.size) {
      errors.push(`Nullifier count mismatch: ${this.nextNullifierIndex} vs ${this.nullifierLeaves.size}`);
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // SEARCH

  findCommitmentsByRange(startIndex: number, endIndex: number): Array<{ hash: Field; index: number }> {
    const commitments: Array<{ hash: Field; index: number }> = [];
    
    this.commitmentLeaves.forEach((index, hashStr) => {
      if (index >= startIndex && index <= endIndex) {
        commitments.push({
          hash: Field.from(BigInt(hashStr)),
          index,
        });
      }
    });
    
    return commitments.sort((a, b) => a.index - b.index);
  }

  findNullifiersByRange(startIndex: number, endIndex: number): Array<{ hash: Field; index: number }> {
    const nullifiers: Array<{ hash: Field; index: number }> = [];
    
    this.nullifierLeaves.forEach((index, hashStr) => {
      if (index >= startIndex && index <= endIndex) {
        nullifiers.push({
          hash: Field.from(BigInt(hashStr)),
          index,
        });
      }
    });
    
    return nullifiers.sort((a, b) => a.index - b.index);
  }

  // RESET

  reset(): void {
    this.commitmentTree = new MerkleTree(32);
    this.nullifierTree = new MerkleTree(32);
    this.commitmentLeaves.clear();
    this.nullifierLeaves.clear();
    this.nextCommitmentIndex = 0;
    this.nextNullifierIndex = 0;
  }
}

// ============================================================================
// MERKLE PROOF VERIFICATION UTILITIES
// ============================================================================

export class MerkleProofVerifier {
  static verifyCommitment(
    leaf: Field,
    witness: CommitmentMerkleWitness,
    expectedRoot: Field
  ): Bool {
    const calculatedRoot = witness.calculateRoot(leaf);
    return calculatedRoot.equals(expectedRoot);
  }

  static verifyNullifierAbsence(
    witness: NullifierMerkleWitness,
    expectedRoot: Field
  ): Bool {
    const calculatedRoot = witness.calculateRoot(Field(0));
    return calculatedRoot.equals(expectedRoot);
  }

  static verifyNullifierPresence(
    nullifier: Field,
    witness: NullifierMerkleWitness,
    expectedRoot: Field
  ): Bool {
    const calculatedRoot = witness.calculateRoot(nullifier);
    return calculatedRoot.equals(expectedRoot);
  }

  static computeRoot(leaf: Field, path: Field[], indices: boolean[]): Field {
    let current = leaf;
    
    for (let i = 0; i < path.length; i++) {
      const sibling = path[i];
      const isLeft = indices[i];
      
      if (isLeft) {
        current = Poseidon.hash([current, sibling]);
      } else {
        current = Poseidon.hash([sibling, current]);
      }
    }
    
    return current;
  }
}

export { MerkleTree };