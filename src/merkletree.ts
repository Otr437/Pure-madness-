// ============================================================================
// X402 MERKLE TREE MANAGER - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 3 of 8
// Full merkle tree implementation for commitments and nullifiers
// Witness generation, proof verification, persistence
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
  private treeHeight: number;

  constructor(height: number = 32) {
    this.treeHeight = height;
    this.commitmentTree = new MerkleTree(height);
    this.nullifierTree = new MerkleTree(height);
    this.commitmentLeaves = new Map();
    this.nullifierLeaves = new Map();
    this.nextCommitmentIndex = 0;
    this.nextNullifierIndex = 0;
  }

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

  getCommitmentWitnessByIndex(index: number): CommitmentMerkleWitness {
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

  getCommitmentAtIndex(index: number): Field {
    return this.commitmentTree.getNode(0, BigInt(index));
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

  getNullifierWitnessByIndex(index: number): NullifierMerkleWitness {
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

  getNullifierAtIndex(index: number): Field {
    return this.nullifierTree.getNode(0, BigInt(index));
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

  getStatistics(): {
    commitmentCount: number;
    nullifierCount: number;
    commitmentRoot: string;
    nullifierRoot: string;
    treeHeight: number;
    maxCapacity: number;
    commitmentUtilization: number;
    nullifierUtilization: number;
  } {
    const maxCapacity = Math.pow(2, this.treeHeight);
    
    return {
      commitmentCount: this.nextCommitmentIndex,
      nullifierCount: this.nextNullifierIndex,
      commitmentRoot: this.commitmentTree.getRoot().toString(),
      nullifierRoot: this.nullifierTree.getRoot().toString(),
      treeHeight: this.treeHeight,
      maxCapacity,
      commitmentUtilization: (this.nextCommitmentIndex / maxCapacity) * 100,
      nullifierUtilization: (this.nextNullifierIndex / maxCapacity) * 100,
    };
  }

  exportState(): {
    commitments: Array<{ hash: string; index: number }>;
    nullifiers: Array<{ hash: string; index: number }>;
    commitmentRoot: string;
    nullifierRoot: string;
    nextCommitmentIndex: number;
    nextNullifierIndex: number;
    treeHeight: number;
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
      treeHeight: this.treeHeight,
    };
  }

  importState(state: {
    commitments: Array<{ hash: string; index: number }>;
    nullifiers: Array<{ hash: string; index: number }>;
    nextCommitmentIndex: number;
    nextNullifierIndex: number;
    treeHeight: number;
  }): void {
    if (state.treeHeight !== this.treeHeight) {
      throw new Error(`Tree height mismatch: expected ${this.treeHeight}, got ${state.treeHeight}`);
    }

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

  async saveToFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const state = this.exportState();
    await fs.writeFile(filepath, JSON.stringify(state, null, 2), 'utf8');
  }

  async loadFromFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const data = await fs.readFile(filepath, 'utf8');
    const state = JSON.parse(data);
    this.importState(state);
  }

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

  validateIntegrity(): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    
    const commitmentIndices = Array.from(this.commitmentLeaves.values()).sort((a, b) => a - b);
    for (let i = 0; i < commitmentIndices.length; i++) {
      if (commitmentIndices[i] !== i) {
        errors.push(`Commitment index gap at ${i}`);
      }
    }
    
    const nullifierIndices = Array.from(this.nullifierLeaves.values()).sort((a, b) => a - b);
    for (let i = 0; i < nullifierIndices.length; i++) {
      if (nullifierIndices[i] !== i) {
        errors.push(`Nullifier index gap at ${i}`);
      }
    }
    
    if (this.nextCommitmentIndex !== this.commitmentLeaves.size) {
      errors.push(`Commitment count mismatch: ${this.nextCommitmentIndex} vs ${this.commitmentLeaves.size}`);
    }
    
    if (this.nextNullifierIndex !== this.nullifierLeaves.size) {
      errors.push(`Nullifier count mismatch: ${this.nextNullifierIndex} vs ${this.nullifierLeaves.size}`);
    }

    this.commitmentLeaves.forEach((index, hashStr) => {
      const leaf = this.commitmentTree.getNode(0, BigInt(index));
      if (leaf.toString() !== hashStr) {
        errors.push(`Commitment tree mismatch at index ${index}`);
      }
    });

    this.nullifierLeaves.forEach((index, hashStr) => {
      const leaf = this.nullifierTree.getNode(0, BigInt(index));
      if (leaf.toString() !== hashStr) {
        errors.push(`Nullifier tree mismatch at index ${index}`);
      }
    });
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

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

  reset(): void {
    this.commitmentTree = new MerkleTree(this.treeHeight);
    this.nullifierTree = new MerkleTree(this.treeHeight);
    this.commitmentLeaves.clear();
    this.nullifierLeaves.clear();
    this.nextCommitmentIndex = 0;
    this.nextNullifierIndex = 0;
  }

  clone(): MerkleTreeManager {
    const cloned = new MerkleTreeManager(this.treeHeight);
    const state = this.exportState();
    cloned.importState(state);
    return cloned;
  }

  getCommitmentPath(index: number): Field[] {
    const path: Field[] = [];
    for (let level = 0; level < this.treeHeight; level++) {
      const siblingIndex = BigInt(index) ^ 1n;
      path.push(this.commitmentTree.getNode(level, siblingIndex));
      index = Math.floor(index / 2);
    }
    return path;
  }

  getNullifierPath(index: number): Field[] {
    const path: Field[] = [];
    for (let level = 0; level < this.treeHeight; level++) {
      const siblingIndex = BigInt(index) ^ 1n;
      path.push(this.nullifierTree.getNode(level, siblingIndex));
      index = Math.floor(index / 2);
    }
    return path;
  }
}

// ============================================================================
// MERKLE PROOF VERIFIER
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
    if (path.length !== indices.length) {
      throw new Error('Path and indices length mismatch');
    }

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

  static verifyPath(
    leaf: Field,
    path: Field[],
    indices: boolean[],
    expectedRoot: Field
  ): boolean {
    const computedRoot = this.computeRoot(leaf, path, indices);
    return computedRoot.equals(expectedRoot).toBoolean();
  }
}

// ============================================================================
// MERKLE TREE UTILITIES
// ============================================================================

export class MerkleTreeUtils {
  static createEmptyTree(height: number): MerkleTree {
    return new MerkleTree(height);
  }

  static getMaxCapacity(height: number): number {
    return Math.pow(2, height);
  }

  static calculateTreeHeight(maxLeaves: number): number {
    return Math.ceil(Math.log2(maxLeaves));
  }

  static isValidIndex(index: number, height: number): boolean {
    const maxIndex = Math.pow(2, height) - 1;
    return index >= 0 && index <= maxIndex;
  }

  static computeSiblingIndex(index: number): number {
    return index ^ 1;
  }

  static computeParentIndex(index: number): number {
    return Math.floor(index / 2);
  }

  static getIndexPath(leafIndex: number, height: number): boolean[] {
    const path: boolean[] = [];
    let index = leafIndex;
    
    for (let i = 0; i < height; i++) {
      path.push((index & 1) === 0);
      index = Math.floor(index / 2);
    }
    
    return path;
  }

  static reconstructTree(leaves: Field[], height: number): MerkleTree {
    const tree = new MerkleTree(height);
    
    leaves.forEach((leaf, index) => {
      tree.setLeaf(BigInt(index), leaf);
    });
    
    return tree;
  }
}

export { MerkleTree };