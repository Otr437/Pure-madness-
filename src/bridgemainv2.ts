// ============================================================================
// X402 CORE BRIDGE CONTRACT - PRODUCTION READY
// ============================================================================

import {
  SmartContract,
  state,
  State,
  method,
  Field,
  Poseidon,
  Bool,
  Provable,
  PublicKey,
  Signature,
  UInt64,
  UInt32,
  Permissions,
  AccountUpdate,
} from 'o1js';

import { CommitmentMerkleWitness, NullifierMerkleWitness } from './merkle-manager';
import { TransferCommitment } from './commitment-system';
import { TransferNullifier } from './nullifier-system';
import { EvmSignatureProof } from './ecdsa-module';
import { RelayerPayment } from './relayer-infrastructure';

export class X402CoreBridge extends SmartContract {
  // STATE
  @state(Field) commitmentsRoot = State<Field>();
  @state(Field) nullifiersRoot = State<Field>();
  @state(Field) depositCount = State<Field>();
  @state(Field) withdrawalCount = State<Field>();
  @state(UInt64) totalValueLocked = State<UInt64>();
  @state(UInt32) protocolFeeBps = State<UInt32>();
  @state(PublicKey) protocolFeeRecipient = State<PublicKey>();
  @state(Bool) isPaused = State<Bool>();
  @state(PublicKey) owner = State<PublicKey>();
  @state(UInt64) withdrawalTimeLock = State<UInt64>();
  @state(UInt64) accumulatedFees = State<UInt64>();

  init() {
    super.init();
    
    const emptyRoot = Field(0);
    this.commitmentsRoot.set(emptyRoot);
    this.nullifiersRoot.set(emptyRoot);
    this.depositCount.set(Field(0));
    this.withdrawalCount.set(Field(0));
    this.totalValueLocked.set(UInt64.from(0));
    this.accumulatedFees.set(UInt64.from(0));
    this.protocolFeeBps.set(UInt32.from(10));
    this.withdrawalTimeLock.set(UInt64.from(300));
    
    const deployer = this.sender.getAndRequireSignature();
    this.protocolFeeRecipient.set(deployer);
    this.owner.set(deployer);
    this.isPaused.set(Bool(false));

    this.account.permissions.set({
      ...Permissions.default(),
      setVerificationKey: Permissions.VerificationKey.impossibleDuringCurrentVersion(),
      setPermissions: Permissions.impossible(),
    });
  }

  @method async deposit(
    amount: UInt64,
    sourceChain: UInt32,
    targetChain: UInt32,
    commitment: TransferCommitment,
    witness: CommitmentMerkleWitness,
    minaSignature: Signature,
    evmProof: EvmSignatureProof,
    isEvmChain: Bool
  ) {
    const paused = this.isPaused.getAndRequireEquals();
    paused.assertFalse('Contract paused');

    amount.value.assertGreaterThan(Field(0));
    amount.value.assertLessThanOrEqual(Field(1000000000000000));
    
    sourceChain.value.equals(targetChain.value).assertFalse();

    const sender = this.sender.getAndRequireSignature();
    
    const minaValid = minaSignature.verify(sender, [
      amount.value,
      commitment.hash,
      sourceChain.value,
      targetChain.value,
    ]);

    const evmValid = evmProof.verify();

    Provable.if(isEvmChain, evmValid, minaValid).assertTrue();

    const currentRoot = this.commitmentsRoot.getAndRequireEquals();
    witness.calculateRoot(Field(0)).assertEquals(currentRoot);

    const newRoot = witness.calculateRoot(commitment.hash);
    this.commitmentsRoot.set(newRoot);

    const count = this.depositCount.getAndRequireEquals();
    this.depositCount.set(count.add(1));

    const feeBps = this.protocolFeeBps.getAndRequireEquals();
    const fee = amount.value.mul(feeBps.value).div(10000);
    const netAmount = amount.value.sub(fee);

    const accFees = this.accumulatedFees.getAndRequireEquals();
    this.accumulatedFees.set(accFees.add(UInt64.from(fee)));

    const tvl = this.totalValueLocked.getAndRequireEquals();
    this.totalValueLocked.set(tvl.add(UInt64.from(netAmount)));

    this.emitEvent('Deposit', {
      commitmentHash: commitment.hash,
      leafIndex: count,
      amount: UInt64.from(netAmount),
      sourceChain,
      targetChain,
      timestamp: this.network.timestamp.getAndRequireEquals(),
      depositor: sender,
    });
  }

  @method async withdraw(
    nullifier: TransferNullifier,
    commitment: TransferCommitment,
    secret: Field,
    recipient: Field,
    commitmentWitness: CommitmentMerkleWitness,
    nullifierWitness: NullifierMerkleWitness,
    relayerPayment: RelayerPayment,
    targetChain: UInt32
  ) {
    const paused = this.isPaused.getAndRequireEquals();
    paused.assertFalse();

    const commRoot = this.commitmentsRoot.getAndRequireEquals();
    commitmentWitness.calculateRoot(commitment.hash).assertEquals(commRoot);

    const nullRoot = this.nullifiersRoot.getAndRequireEquals();
    nullifierWitness.calculateRoot(Field(0)).assertEquals(nullRoot);

    commitment.verify(recipient, secret).assertTrue();
    nullifier.verify(secret).assertTrue();

    const currentTime = this.network.timestamp.getAndRequireEquals();
    commitment.isExpired(currentTime).assertFalse();
    relayerPayment.isExpired(currentTime).assertFalse();

    relayerPayment.verifySignature(commitment.hash).assertTrue();

    const maxRelayerFee = commitment.amount.value.mul(5).div(100);
    relayerPayment.feeAmount.value.assertLessThanOrEqual(maxRelayerFee);

    const newNullRoot = nullifierWitness.calculateRoot(nullifier.hash);
    this.nullifiersRoot.set(newNullRoot);

    const count = this.withdrawalCount.getAndRequireEquals();
    this.withdrawalCount.set(count.add(1));

    const tvl = this.totalValueLocked.getAndRequireEquals();
    this.totalValueLocked.set(tvl.sub(commitment.amount));

    const netAmount = commitment.amount.sub(relayerPayment.feeAmount);

    this.send({ to: relayerPayment.relayerPubKey, amount: relayerPayment.feeAmount });

    this.emitEvent('Withdrawal', {
      nullifierHash: nullifier.hash,
      recipientHash: commitment.recipientHash,
      amount: netAmount,
      targetChain,
      relayerFee: relayerPayment.feeAmount,
      relayer: relayerPayment.relayerPubKey,
      timestamp: currentTime,
    });
  }

  @method async pause(reason: Field) {
    const sender = this.sender.getAndRequireSignature();
    const owner = this.owner.getAndRequireEquals();
    sender.assertEquals(owner);

    this.isPaused.set(Bool(true));

    this.emitEvent('EmergencyPause', {
      pausedBy: sender,
      reason,
      timestamp: this.network.timestamp.getAndRequireEquals(),
    });
  }

  @method async unpause() {
    const sender = this.sender.getAndRequireSignature();
    const owner = this.owner.getAndRequireEquals();
    sender.assertEquals(owner);

    this.isPaused.set(Bool(false));
  }

  @method async updateProtocolFee(newFeeBps: UInt32) {
    const sender = this.sender.getAndRequireSignature();
    const owner = this.owner.getAndRequireEquals();
    sender.assertEquals(owner);

    newFeeBps.value.assertLessThanOrEqual(Field(100));

    const oldFee = this.protocolFeeBps.getAndRequireEquals();
    this.protocolFeeBps.set(newFeeBps);

    this.emitEvent('ProtocolFeeUpdate', {
      oldFeeBps: oldFee,
      newFeeBps,
      updatedBy: sender,
      timestamp: this.network.timestamp.getAndRequireEquals(),
    });
  }

  @method async claimFees() {
    const sender = this.sender.getAndRequireSignature();
    const recipient = this.protocolFeeRecipient.getAndRequireEquals();
    sender.assertEquals(recipient);

    const fees = this.accumulatedFees.getAndRequireEquals();
    fees.value.assertGreaterThan(Field(0));

    this.send({ to: recipient, amount: fees });
    this.accumulatedFees.set(UInt64.from(0));
  }

  @method async transferOwnership(newOwner: PublicKey) {
    const sender = this.sender.getAndRequireSignature();
    const owner = this.owner.getAndRequireEquals();
    sender.assertEquals(owner);

    this.owner.set(newOwner);
  }
}