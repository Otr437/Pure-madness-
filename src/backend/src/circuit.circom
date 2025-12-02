pragma circom 2.2.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/switcher.circom";

// Merkle tree verification for membership proof
// Uses Switcher from circomlib for proper left/right selection
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component selectors[levels];
    component hashers[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Constrain pathIndices to be binary (0 or 1)
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Use Switcher component from circomlib
        // When pathIndices[i] = 0: outL = levelHashes[i], outR = pathElements[i]
        // When pathIndices[i] = 1: outL = pathElements[i], outR = levelHashes[i]
        selectors[i] = Switcher();
        selectors[i].sel <== pathIndices[i];
        selectors[i].L <== levelHashes[i];
        selectors[i].R <== pathElements[i];

        // Hash the two values in order
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].outL;
        hashers[i].inputs[1] <== selectors[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    // Final constraint: computed root must match provided root
    root === levelHashes[levels];
}

// Range check to ensure amounts are within valid bounds
template RangeCheck(bits) {
    signal input in;
    signal input min;
    signal input max;
    
    // Convert to bits to ensure it fits in the bit range
    component n2b = Num2Bits(bits);
    n2b.in <== in;
    
    // Check: in >= min
    component gtMin = GreaterEqThan(bits);
    gtMin.in[0] <== in;
    gtMin.in[1] <== min;
    gtMin.out === 1;
    
    // Check: in <= max
    component ltMax = LessEqThan(bits);
    ltMax.in[0] <== in;
    ltMax.in[1] <== max;
    ltMax.out === 1;
}

// Main private swap circuit with cross-chain support
template PrivateSwap(levels) {
    // ============================================
    // PRIVATE INPUTS (hidden from verifier)
    // ============================================
    signal input secret;              // Secret value for commitment
    signal input senderKey;           // Sender's private key
    signal input amountIn;            // Input amount
    signal input amountOut;           // Output amount
    signal input recipient;           // Recipient address
    signal input chainIdFrom;         // Source chain ID
    signal input chainIdTo;           // Destination chain ID
    signal input tokenFrom;           // Source token address
    signal input tokenTo;             // Destination token address
    signal input timestamp;           // Transaction timestamp
    signal input nonce;               // Unique transaction nonce
    
    // Merkle proof inputs (private)
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // ============================================
    // PUBLIC INPUTS (visible to verifier)
    // ============================================
    signal input merkleRoot;          // Current merkle root
    signal input minAmount;           // Minimum allowed amount
    signal input maxAmount;           // Maximum allowed amount
    signal input currentTime;         // Current block timestamp
    
    // ============================================
    // PUBLIC OUTPUTS
    // ============================================
    signal output nullifierHash;      // Prevents double-spending
    signal output commitmentOut;      // New commitment for recipient
    signal output rootAfter;          // Updated merkle root
    signal output amountInPublic;     // Public amount for validation
    signal output chainIdToPublic;    // Public chain ID for routing
    signal output swapHash;           // Unique swap identifier
    
    // ============================================
    // STEP 1: Create and verify input commitment
    // ============================================
    component commitmentHasher = Poseidon(5);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== senderKey;
    commitmentHasher.inputs[2] <== amountIn;
    commitmentHasher.inputs[3] <== chainIdFrom;
    commitmentHasher.inputs[4] <== tokenFrom;
    
    // Verify commitment exists in merkle tree
    component merkleChecker = MerkleTreeChecker(levels);
    merkleChecker.leaf <== commitmentHasher.out;
    merkleChecker.root <== merkleRoot;
    for (var i = 0; i < levels; i++) {
        merkleChecker.pathElements[i] <== pathElements[i];
        merkleChecker.pathIndices[i] <== pathIndices[i];
    }
    
    // ============================================
    // STEP 2: Generate nullifier (anti-double-spend)
    // ============================================
    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== nonce;
    nullifierHasher.inputs[2] <== chainIdFrom;
    nullifierHasher.inputs[3] <== senderKey;
    nullifierHash <== nullifierHasher.out;
    
    // ============================================
    // STEP 3: Create output commitment for recipient
    // ============================================
    component outputHasher = Poseidon(5);
    outputHasher.inputs[0] <== secret;
    outputHasher.inputs[1] <== recipient;
    outputHasher.inputs[2] <== amountOut;
    outputHasher.inputs[3] <== chainIdTo;
    outputHasher.inputs[4] <== tokenTo;
    commitmentOut <== outputHasher.out;
    
    // ============================================
    // STEP 4: Calculate new merkle root
    // ============================================
    component rootHasher = Poseidon(2);
    rootHasher.inputs[0] <== merkleRoot;
    rootHasher.inputs[1] <== commitmentOut;
    rootAfter <== rootHasher.out;
    
    // ============================================
    // STEP 5: Generate swap hash for verification
    // ============================================
    component swapHasher = Poseidon(8);
    swapHasher.inputs[0] <== nullifierHash;
    swapHasher.inputs[1] <== commitmentOut;
    swapHasher.inputs[2] <== amountIn;
    swapHasher.inputs[3] <== amountOut;
    swapHasher.inputs[4] <== chainIdFrom;
    swapHasher.inputs[5] <== chainIdTo;
    swapHasher.inputs[6] <== timestamp;
    swapHasher.inputs[7] <== nonce;
    swapHash <== swapHasher.out;
    
    // ============================================
    // STEP 6: Set public outputs
    // ============================================
    amountInPublic <== amountIn;
    chainIdToPublic <== chainIdTo;
    
    // ============================================
    // STEP 7: Range checks for amounts
    // ============================================
    component rangeCheckIn = RangeCheck(64);
    rangeCheckIn.in <== amountIn;
    rangeCheckIn.min <== minAmount;
    rangeCheckIn.max <== maxAmount;
    
    component rangeCheckOut = RangeCheck(64);
    rangeCheckOut.in <== amountOut;
    rangeCheckOut.min <== minAmount;
    rangeCheckOut.max <== maxAmount;
    
    // ============================================
    // STEP 8: Timestamp validation
    // ============================================
    // Reject timestamps too far in the future (max 1 hour)
    component timestampCheckFuture = LessThan(64);
    timestampCheckFuture.in[0] <== timestamp;
    timestampCheckFuture.in[1] <== currentTime + 3600;
    timestampCheckFuture.out === 1;
    
    // Reject timestamps too far in the past (max 24 hours)
    component timestampCheckPast = GreaterThan(64);
    timestampCheckPast.in[0] <== timestamp;
    timestampCheckPast.in[1] <== currentTime - 86400;
    timestampCheckPast.out === 1;
    
    // ============================================
    // STEP 9: Cross-chain validation
    // ============================================
    // Ensure source and destination chains are different
    component chainCheck = IsEqual();
    chainCheck.in[0] <== chainIdFrom;
    chainCheck.in[1] <== chainIdTo;
    chainCheck.out === 0;
    
    // ============================================
    // STEP 10: Non-zero value checks
    // ============================================
    // Verify amountIn is non-zero
    component amountInCheck = IsZero();
    amountInCheck.in <== amountIn;
    amountInCheck.out === 0;
    
    // Verify amountOut is non-zero
    component amountOutCheck = IsZero();
    amountOutCheck.in <== amountOut;
    amountOutCheck.out === 0;
    
    // Verify recipient is non-zero
    component recipientCheck = IsZero();
    recipientCheck.in <== recipient;
    recipientCheck.out === 0;
    
    // Verify secret is non-zero
    component secretCheck = IsZero();
    secretCheck.in <== secret;
    secretCheck.out === 0;
    
    // Verify tokenFrom is non-zero
    component tokenFromCheck = IsZero();
    tokenFromCheck.in <== tokenFrom;
    tokenFromCheck.out === 0;
    
    // Verify tokenTo is non-zero
    component tokenToCheck = IsZero();
    tokenToCheck.in <== tokenTo;
    tokenToCheck.out === 0;
    
    // ============================================
    // STEP 11: Under-constraint protection
    // ============================================
    // Square unused private inputs to ensure they are bound to witness
    // This prevents witness tampering attacks where unconstrained
    // signals could be modified without affecting the proof
    // This is CRITICAL for security in Circom circuits
    signal recipientSquared;
    signal timestampSquared;
    signal nonceSquared;
    
    recipientSquared <== recipient * recipient;
    timestampSquared <== timestamp * timestamp;
    nonceSquared <== nonce * nonce;
}

// Instantiate with 20 levels (supports ~1M leaves = 2^20)
// Public inputs: merkleRoot, minAmount, maxAmount, currentTime
component main {public [merkleRoot, minAmount, maxAmount, currentTime]} = PrivateSwap(20);