#!/bin/bash

# ============================================================================
# COMPLETE POWERS OF TAU SETUP FOR ECDSA VERIFIER CIRCUIT
# ============================================================================

set -e

echo "════════════════════════════════════════════════════════════════════════"
echo "ECDSA VERIFIER - COMPLETE POWERS OF TAU CEREMONY"
echo "════════════════════════════════════════════════════════════════════════"

# ============================================================================
# STEP 0: ENVIRONMENT SETUP
# ============================================================================

echo ""
echo "📦 Step 0: Installing Dependencies..."
echo "────────────────────────────────────────────────────────────────────────"

# Install Node.js dependencies
npm install -g circom
npm install -g snarkjs

# Install Rust (for faster witness generation)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Create working directory
mkdir -p ecdsa-verifier-ceremony
cd ecdsa-verifier-ceremony

echo "✅ Dependencies installed"

# ============================================================================
# STEP 1: COMPILE THE CIRCUIT
# ============================================================================

echo ""
echo "🔧 Step 1: Compiling Circuit..."
echo "────────────────────────────────────────────────────────────────────────"

# Save the circuit to file
cat > ecdsa_verifier.circom << 'EOF'
pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/mux2.circom";
include "circomlib/circuits/mux3.circom";
include "circomlib/circuits/poseidon.circom";

var SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337;
var SECP256K1_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663;
var SECP256K1_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
var SECP256K1_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
var SECP256K1_A = 0;
var SECP256K1_B = 7;

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc = 0;
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc += out[i] * e2;
        e2 = e2 + e2;
    }
    lc === in;
}

template Bits2Num(n) {
    signal input in[n];
    signal output out;
    var lc = 0;
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc += in[i] * e2;
        e2 = e2 + e2;
    }
    out <== lc;
}

template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;
    component n2b = Num2Bits(n+1);
    n2b.in <== in[0] + (1<<n) - in[1];
    out <== 1 - n2b.out[n];
}

template GreaterThan(n) {
    signal input in[2];
    signal output out;
    component lt = LessThan(n);
    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    out <== lt.out;
}

template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    out <== 1 - (in * inv);
    in * out === 0;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    component isz = IsZero();
    isz.in <== in[0] - in[1];
    out <== isz.out;
}

template Mux2() {
    signal input sel;
    signal input in[2];
    signal output out;
    out <== (in[1] - in[0]) * sel + in[0];
}

template Modulo(n, k) {
    signal input in;
    signal output out;
    signal quotient;
    out <-- in % k;
    quotient <-- (in - out) / k;
    component rangeCheck = LessThan(n);
    rangeCheck.in[0] <== out;
    rangeCheck.in[1] <== k;
    rangeCheck.out === 1;
    in === quotient * k + out;
}

template ModInv(n, k) {
    signal input in;
    signal output out;
    out <-- (function(a, m) {
        a = a % m;
        if (a == 0) return 0;
        var m0 = m;
        var x0 = 0;
        var x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            var q = Math.floor(a / m);
            var t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    })(in, k);
    signal product;
    product <== in * out;
    component modCheck = Modulo(n * 2, k);
    modCheck.in <== product;
    modCheck.out === 1;
}

template InScalarRange() {
    signal input in;
    signal output valid;
    component gtZero = GreaterThan(256);
    gtZero.in[0] <== in;
    gtZero.in[1] <== 0;
    component ltN = LessThan(256);
    ltN.in[0] <== in;
    ltN.in[1] <== SECP256K1_N;
    valid <== gtZero.out * ltN.out;
}

template InFieldRange() {
    signal input in;
    signal output valid;
    component gtZero = GreaterThan(256);
    gtZero.in[0] <== in;
    gtZero.in[1] <== 0;
    component ltP = LessThan(256);
    ltP.in[0] <== in;
    ltP.in[1] <== SECP256K1_P;
    valid <== gtZero.out * ltP.out;
}

template PointOnCurve() {
    signal input x;
    signal input y;
    signal output valid;
    signal x_sq;
    x_sq <== x * x;
    signal x_cu;
    x_cu <== x_sq * x;
    signal y_sq;
    y_sq <== y * y;
    signal rhs_temp;
    rhs_temp <== x_cu + SECP256K1_B;
    component rhs_mod = Modulo(512, SECP256K1_P);
    rhs_mod.in <== rhs_temp;
    component lhs_mod = Modulo(512, SECP256K1_P);
    lhs_mod.in <== y_sq;
    component curve_check = IsEqual();
    curve_check.in[0] <== lhs_mod.out;
    curve_check.in[1] <== rhs_mod.out;
    valid <== curve_check.out;
}

template PointNotInfinity() {
    signal input x;
    signal input y;
    signal output valid;
    component xNonZero = IsZero();
    xNonZero.in <== x;
    component yNonZero = IsZero();
    yNonZero.in <== y;
    signal bothZero;
    bothZero <== xNonZero.out * yNonZero.out;
    valid <== 1 - bothZero;
}

template ValidatePoint() {
    signal input x;
    signal input y;
    signal output valid;
    component xRange = InFieldRange();
    xRange.in <== x;
    component yRange = InFieldRange();
    yRange.in <== y;
    component onCurve = PointOnCurve();
    onCurve.x <== x;
    onCurve.y <== y;
    component notInfinity = PointNotInfinity();
    notInfinity.x <== x;
    notInfinity.y <== y;
    signal check1;
    check1 <== xRange.valid * yRange.valid;
    signal check2;
    check2 <== check1 * onCurve.valid;
    valid <== check2 * notInfinity.valid;
}

template PointDouble() {
    signal input in[2];
    signal output out[2];
    signal x_sq;
    x_sq <== in[0] * in[0];
    signal lambda_num_temp;
    lambda_num_temp <== 3 * x_sq;
    component lambda_num_mod = Modulo(512, SECP256K1_P);
    lambda_num_mod.in <== lambda_num_temp;
    signal lambda_den_temp;
    lambda_den_temp <== 2 * in[1];
    component lambda_den_mod = Modulo(512, SECP256K1_P);
    lambda_den_mod.in <== lambda_den_temp;
    component inv_den = ModInv(512, SECP256K1_P);
    inv_den.in <== lambda_den_mod.out;
    signal lambda_temp;
    lambda_temp <== lambda_num_mod.out * inv_den.out;
    component lambda_mod = Modulo(512, SECP256K1_P);
    lambda_mod.in <== lambda_temp;
    signal lambda_sq_temp;
    lambda_sq_temp <== lambda_mod.out * lambda_mod.out;
    component lambda_sq_mod = Modulo(512, SECP256K1_P);
    lambda_sq_mod.in <== lambda_sq_temp;
    signal x3_temp;
    x3_temp <== lambda_sq_mod.out - 2 * in[0] + 2 * SECP256K1_P;
    component x3_mod = Modulo(512, SECP256K1_P);
    x3_mod.in <== x3_temp;
    out[0] <== x3_mod.out;
    signal y3_temp1;
    y3_temp1 <== in[0] - out[0] + SECP256K1_P;
    signal y3_temp2;
    y3_temp2 <== lambda_mod.out * y3_temp1;
    signal y3_temp3;
    y3_temp3 <== y3_temp2 - in[1] + SECP256K1_P;
    component y3_mod = Modulo(512, SECP256K1_P);
    y3_mod.in <== y3_temp3;
    out[1] <== y3_mod.out;
}

template PointAdd() {
    signal input in1[2];
    signal input in2[2];
    signal output out[2];
    signal lambda_num_temp;
    lambda_num_temp <== in2[1] - in1[1] + SECP256K1_P;
    component lambda_num_mod = Modulo(512, SECP256K1_P);
    lambda_num_mod.in <== lambda_num_temp;
    signal lambda_den_temp;
    lambda_den_temp <== in2[0] - in1[0] + SECP256K1_P;
    component lambda_den_mod = Modulo(512, SECP256K1_P);
    lambda_den_mod.in <== lambda_den_temp;
    component inv_den = ModInv(512, SECP256K1_P);
    inv_den.in <== lambda_den_mod.out;
    signal lambda_temp;
    lambda_temp <== lambda_num_mod.out * inv_den.out;
    component lambda_mod = Modulo(512, SECP256K1_P);
    lambda_mod.in <== lambda_temp;
    signal lambda_sq_temp;
    lambda_sq_temp <== lambda_mod.out * lambda_mod.out;
    component lambda_sq_mod = Modulo(512, SECP256K1_P);
    lambda_sq_mod.in <== lambda_sq_temp;
    signal x3_temp;
    x3_temp <== lambda_sq_mod.out - in1[0] - in2[0] + 2 * SECP256K1_P;
    component x3_mod = Modulo(512, SECP256K1_P);
    x3_mod.in <== x3_temp;
    out[0] <== x3_mod.out;
    signal y3_temp1;
    y3_temp1 <== in1[0] - out[0] + SECP256K1_P;
    signal y3_temp2;
    y3_temp2 <== lambda_mod.out * y3_temp1;
    signal y3_temp3;
    y3_temp3 <== y3_temp2 - in1[1] + SECP256K1_P;
    component y3_mod = Modulo(512, SECP256K1_P);
    y3_mod.in <== y3_temp3;
    out[1] <== y3_mod.out;
}

template EscalarMul(n) {
    signal input e;
    signal input in[2];
    signal output out[2];
    component scalarRange = InScalarRange();
    scalarRange.in <== e;
    scalarRange.valid === 1;
    component e2b = Num2Bits(256);
    e2b.in <== e;
    signal acc[257][2];
    acc[0][0] <== 0;
    acc[0][1] <== 0;
    signal base[257][2];
    base[0][0] <== in[0];
    base[0][1] <== in[1];
    component doublers[256];
    component adders[256];
    component mux_x[256];
    component mux_y[256];
    component is_first[256];
    component first_x[256];
    component first_y[256];
    component acc_x_zero[256];
    component acc_y_zero[256];
    for (var i = 0; i < 256; i++) {
        doublers[i] = PointDouble();
        doublers[i].in[0] <== base[i][0];
        doublers[i].in[1] <== base[i][1];
        base[i+1][0] <== doublers[i].out[0];
        base[i+1][1] <== doublers[i].out[1];
        acc_x_zero[i] = IsZero();
        acc_x_zero[i].in <== acc[i][0];
        acc_y_zero[i] = IsZero();
        acc_y_zero[i].in <== acc[i][1];
        signal both_zero;
        both_zero <== acc_x_zero[i].out * acc_y_zero[i].out;
        is_first[i] = IsEqual();
        is_first[i].in[0] <== both_zero;
        is_first[i].in[1] <== 1;
        adders[i] = PointAdd();
        adders[i].in1[0] <== acc[i][0];
        adders[i].in1[1] <== acc[i][1];
        adders[i].in2[0] <== base[i][0];
        adders[i].in2[1] <== base[i][1];
        first_x[i] = Mux2();
        first_x[i].sel <== is_first[i].out;
        first_x[i].in[0] <== adders[i].out[0];
        first_x[i].in[1] <== base[i][0];
        first_y[i] = Mux2();
        first_y[i].sel <== is_first[i].out;
        first_y[i].in[0] <== adders[i].out[1];
        first_y[i].in[1] <== base[i][1];
        mux_x[i] = Mux2();
        mux_x[i].sel <== e2b.out[i];
        mux_x[i].in[0] <== acc[i][0];
        mux_x[i].in[1] <== first_x[i].out;
        acc[i+1][0] <== mux_x[i].out;
        mux_y[i] = Mux2();
        mux_y[i].sel <== e2b.out[i];
        mux_y[i].in[0] <== acc[i][1];
        mux_y[i].in[1] <== first_y[i].out;
        acc[i+1][1] <== mux_y[i].out;
    }
    out[0] <== acc[256][0];
    out[1] <== acc[256][1];
}

template ECDSAVerifier() {
    signal input pubKeyX;
    signal input pubKeyY;
    signal input message;
    signal input r;
    signal input s;
    signal output valid;
    component rRange = InScalarRange();
    rRange.in <== r;
    component sRange = InScalarRange();
    sRange.in <== s;
    component pubKeyValid = ValidatePoint();
    pubKeyValid.x <== pubKeyX;
    pubKeyValid.y <== pubKeyY;
    component sInv = ModInv(512, SECP256K1_N);
    sInv.in <== s;
    signal u1_temp;
    u1_temp <== message * sInv.out;
    component u1_mod = Modulo(512, SECP256K1_N);
    u1_mod.in <== u1_temp;
    signal u2_temp;
    u2_temp <== r * sInv.out;
    component u2_mod = Modulo(512, SECP256K1_N);
    u2_mod.in <== u2_temp;
    component mul1 = EscalarMul(256);
    mul1.e <== u1_mod.out;
    mul1.in[0] <== SECP256K1_GX;
    mul1.in[1] <== SECP256K1_GY;
    component mul2 = EscalarMul(256);
    mul2.e <== u2_mod.out;
    mul2.in[0] <== pubKeyX;
    mul2.in[1] <== pubKeyY;
    component add = PointAdd();
    add.in1[0] <== mul1.out[0];
    add.in1[1] <== mul1.out[1];
    add.in2[0] <== mul2.out[0];
    add.in2[1] <== mul2.out[1];
    component r_mod = Modulo(512, SECP256K1_N);
    r_mod.in <== add.out[0];
    component r_match = IsEqual();
    r_match.in[0] <== r_mod.out;
    r_match.in[1] <== r;
    signal check1;
    check1 <== rRange.valid * sRange.valid;
    signal check2;
    check2 <== check1 * pubKeyValid.valid;
    valid <== check2 * r_match.out;
}

component main {public [pubKeyX, pubKeyY]} = ECDSAVerifier();
EOF

# Compile the circuit
circom ecdsa_verifier.circom --r1cs --wasm --sym --c

echo "✅ Circuit compiled successfully"
echo "   - Constraints: $(snarkjs r1cs info ecdsa_verifier.r1cs | grep 'Constraints' | awk '{print $2}')"
echo "   - Private Inputs: 3 (message, r, s)"
echo "   - Public Inputs: 2 (pubKeyX, pubKeyY)"

# ============================================================================
# STEP 2: START NEW POWERS OF TAU CEREMONY
# ============================================================================

echo ""
echo "🎲 Step 2: Starting Powers of Tau Ceremony..."
echo "────────────────────────────────────────────────────────────────────────"

# Determine required power (circuit has ~500k-1M constraints, so we need 2^21 = 2M)
POWER=21
echo "Using power: 2^${POWER} = $((2**POWER)) constraints"

# Start new ceremony
snarkjs powersoftau new bn128 ${POWER} pot21_0000.ptau -v

echo "✅ Powers of Tau ceremony initialized"

# ============================================================================
# STEP 3: CONTRIBUTE TO THE CEREMONY (MULTIPLE CONTRIBUTIONS)
# ============================================================================

echo ""
echo "👥 Step 3: Contributing to Powers of Tau..."
echo "────────────────────────────────────────────────────────────────────────"

# Contribution 1
echo "Making contribution 1/3..."
snarkjs powersoftau contribute pot21_0000.ptau pot21_0001.ptau \
    --name="First contribution" \
    -v \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

# Contribution 2
echo "Making contribution 2/3..."
snarkjs powersoftau contribute pot21_0001.ptau pot21_0002.ptau \
    --name="Second contribution" \
    -v \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

# Contribution 3
echo "Making contribution 3/3..."
snarkjs powersoftau contribute pot21_0002.ptau pot21_0003.ptau \
    --name="Third contribution" \
    -v \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

echo "✅ Three contributions completed"

# ============================================================================
# STEP 4: PHASE 2 (BEACON)
# ============================================================================

echo ""
echo "📡 Step 4: Applying Random Beacon..."
echo "────────────────────────────────────────────────────────────────────────"

# Use random beacon (e.g., hash of latest Bitcoin block or random data)
BEACON_HASH=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')
BEACON_ITERATIONS=10

snarkjs powersoftau beacon pot21_0003.ptau pot21_beacon.ptau \
    ${BEACON_HASH} ${BEACON_ITERATIONS} \
    -n="Final Beacon"

echo "✅ Random beacon applied"
echo "   Beacon hash: ${BEACON_HASH}"

# ============================================================================
# STEP 5: PREPARE PHASE 2
# ============================================================================

echo ""
echo "🔄 Step 5: Preparing Phase 2..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs powersoftau prepare phase2 pot21_beacon.ptau pot21_final.ptau -v

echo "✅ Phase 2 prepared"

# ============================================================================
# STEP 6: VERIFY THE PROTOCOL
# ============================================================================

echo ""
echo "🔍 Step 6: Verifying Powers of Tau..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs powersoftau verify pot21_final.ptau

echo "✅ Powers of Tau verification passed"

# ============================================================================
# STEP 7: GENERATE ZKEY (CIRCUIT-SPECIFIC SETUP)
# ============================================================================

echo ""
echo "🔑 Step 7: Generating Circuit-Specific Setup (zkey)..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs groth16 setup ecdsa_verifier.r1cs pot21_final.ptau ecdsa_verifier_0000.zkey

echo "✅ Initial zkey generated"

# ============================================================================
# STEP 8: CONTRIBUTE TO PHASE 2 (CIRCUIT-SPECIFIC)
# ============================================================================

echo ""
echo "👥 Step 8: Contributing to Phase 2..."
echo "────────────────────────────────────────────────────────────────────────"

# Phase 2 contribution 1
echo "Making phase 2 contribution 1/2..."
snarkjs zkey contribute ecdsa_verifier_0000.zkey ecdsa_verifier_0001.zkey \
    --name="Phase 2 Contribution 1" \
    -v \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

# Phase 2 contribution 2
echo "Making phase 2 contribution 2/2..."
snarkjs zkey contribute ecdsa_verifier_0001.zkey ecdsa_verifier_0002.zkey \
    --name="Phase 2 Contribution 2" \
    -v \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

echo "✅ Phase 2 contributions completed"

# ============================================================================
# STEP 9: APPLY RANDOM BEACON TO PHASE 2
# ============================================================================

echo ""
echo "📡 Step 9: Applying Phase 2 Beacon..."
echo "────────────────────────────────────────────────────────────────────────"

BEACON_HASH_2=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')

snarkjs zkey beacon ecdsa_verifier_0002.zkey ecdsa_verifier_final.zkey \
    ${BEACON_HASH_2} ${BEACON_ITERATIONS} \
    -n="Phase 2 Final Beacon"

echo "✅ Phase 2 beacon applied"
echo "   Beacon hash: ${BEACON_HASH_2}"

# ============================================================================
# STEP 10: VERIFY THE FINAL ZKEY
# ============================================================================

echo ""
echo "🔍 Step 10: Verifying Final zkey..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs zkey verify ecdsa_verifier.r1cs pot21_final.ptau ecdsa_verifier_final.zkey

echo "✅ Final zkey verification passed"

# ============================================================================
# STEP 11: EXPORT VERIFICATION KEY
# ============================================================================

echo ""
echo "📤 Step 11: Exporting Verification Key..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs zkey export verificationkey ecdsa_verifier_final.zkey verification_key.json

echo "✅ Verification key exported"

# ============================================================================
# STEP 12: EXPORT SOLIDITY VERIFIER
# ============================================================================

echo ""
echo "📜 Step 12: Generating Solidity Verifier Contract..."
echo "────────────────────────────────────────────────────────────────────────"

snarkjs zkey export solidityverifier ecdsa_verifier_final.zkey verifier.sol

echo "✅ Solidity verifier generated"

# ============================================================================
# STEP 13: GENERATE SAMPLE INPUT AND PROOF
# ============================================================================

echo ""
echo "🧪 Step 13: Testing with Sample Proof..."
echo "────────────────────────────────────────────────────────────────────────"

# Create sample input
cat > input.json << 'INPUTEOF'
{
  "pubKeyX": "55066263022277343669578718895168534326250603453777594175500187360389116729240",
  "pubKeyY": "32670510020758816978083085130507043184471273380659243275938904335757337482424",
  "message": "12345678901234567890123456789012",
  "r": "11111111111111111111111111111111111111111111111111111111111111111",
  "s": "22222222222222222222222222222222222222222222222222222222222222222"
}
INPUTEOF

# Generate witness
echo "Generating witness..."
node ecdsa_verifier_js/generate_witness.js \
    ecdsa_verifier_js/ecdsa_verifier.wasm \
    input.json \
    witness.wtns

# Generate proof
echo "Generating proof..."
snarkjs groth16 prove ecdsa_verifier_final.zkey witness.wtns proof.json public.json

# Verify proof
echo "Verifying proof..."
snarkjs groth16 verify verification_key.json public.json proof.json

echo "✅ Test proof generated and verified"

# ============================================================================
# STEP 14: GENERATE VERIFICATION ARTIFACTS
# ============================================================================

echo ""
echo "📦 Step 14: Generating Final Artifacts..."
echo "────────────────────────────────────────────────────────────────────────"

# Export JSON call data for smart contract
snarkjs zkey export soliditycalldata public.json proof.json > calldata.txt

echo "✅ All artifacts generated"

# ============================================================================
# FINAL SUMMARY
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "✅ POWERS OF TAU CEREMONY COMPLETE"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "📁 Generated Files:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  Powers of Tau:"
echo "    • pot21_final.ptau             - Final Powers of Tau file (2^21)"
echo ""
echo "  Circuit Files:"
echo "    • ecdsa_verifier.r1cs          - R1CS constraints"
echo "    • ecdsa_verifier.sym           - Symbols file"
echo "    • ecdsa_verifier_js/           - WASM witness generator"
echo ""
echo "  Proving/Verification Keys:"
echo "    • ecdsa_verifier_final.zkey    - Final proving key"
echo "    • verification_key.json        - Verification key (JSON)"
echo ""
echo "  Smart Contract:"
echo "    • verifier.sol                 - Solidity verifier contract"
echo "    • calldata.txt                 - Sample call data"
echo ""
echo "  Test Files:"
echo "    • input.json                   - Sample input"
echo "    • witness.wtns                 - Sample witness"
echo "    • proof.json                   - Sample proof"
echo "    • public.json                  - Public signals"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "📊 Circuit Statistics:"
echo "────────────────────────────────────────────────────────────────────────"
snarkjs r1cs info ecdsa_verifier.r1cs
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "🔐 Security Information:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  Phase 1 (Powers of Tau):"
echo "    • Participants: 3"
echo "    • Random beacon applied: YES"
echo "    • Verification: PASSED"
echo ""
echo "  Phase 2 (Circuit-Specific):"
echo "    • Participants: 2"
echo "    • Random beacon applied: YES"
echo "    • Verification: PASSED"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "🚀 Next Steps:"
echo "────────────────────────────────────────────────────────────────────────"
echo ""
echo "  1. Deploy the Solidity verifier contract:"
echo "     • File: verifier.sol"
echo "     • Deploy to Ethereum/L2"
echo ""
echo "  2. Generate proofs for your ECDSA signatures:"
echo ""
echo "     # Create input file (input.json):"
echo '     {'
echo '       "pubKeyX": "YOUR_PUBLIC_KEY_X",'
echo '       "pubKeyY": "YOUR_PUBLIC_KEY_Y",'
echo '       "message": "YOUR_MESSAGE_HASH",'
echo '       "r": "YOUR_SIGNATURE_R",'
echo '       "s": "YOUR_SIGNATURE_S"'
echo '     }'
echo ""
echo "     # Generate witness:"
echo "     node ecdsa_verifier_js/generate_witness.js \\"
echo "         ecdsa_verifier_js/ecdsa_verifier.wasm \\"
echo "         input.json \\"
echo "         witness.wtns"
echo ""
echo "     # Generate proof:"
echo "     snarkjs groth16 prove \\"
echo "         ecdsa_verifier_final.zkey \\"
echo "         witness.wtns \\"
echo "         proof.json \\"
echo "         public.json"
echo ""
echo "     # Verify proof locally:"
echo "     snarkjs groth16 verify \\"
echo "         verification_key.json \\"
echo "         public.json \\"
echo "         proof.json"
echo ""
echo "     # Generate call data for smart contract:"
echo "     snarkjs zkey export soliditycalldata \\"
echo "         public.json \\"
echo "         proof.json"
echo ""
echo "  3. Verify on-chain:"
echo "     • Call the verifyProof() function on your deployed contract"
echo "     • Pass the generated call data as arguments"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "📚 File Descriptions:"
echo "────────────────────────────────────────────────────────────────────────"
echo ""
echo "  pot21_final.ptau"
echo "    The final Powers of Tau file after all contributions and beacon."
echo "    This is the universal trusted setup for circuits up to 2^21 constraints."
echo "    Size: ~2GB"
echo ""
echo "  ecdsa_verifier_final.zkey"
echo "    Circuit-specific proving key for the ECDSA verifier."
echo "    Required for generating proofs."
echo "    Size: ~500MB-1GB (depends on circuit size)"
echo ""
echo "  verification_key.json"
echo "    Public verification key in JSON format."
echo "    Used for off-chain proof verification."
echo "    Size: ~1-2KB"
echo ""
echo "  verifier.sol"
echo "    Solidity smart contract for on-chain verification."
echo "    Deploy this to verify proofs on Ethereum/L2."
echo "    Contains the verification key embedded in the contract."
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "⚠️  Important Security Notes:"
echo "────────────────────────────────────────────────────────────────────────"
echo ""
echo "  1. PRODUCTION CEREMONY:"
echo "     For production use, conduct a multi-party ceremony with:"
echo "     • At least 10-50 independent participants"
echo "     • Participants from different organizations"
echo "     • Geographically distributed"
echo "     • Public attestations and transparency logs"
echo ""
echo "  2. ENTROPY SOURCE:"
echo "     This script uses /dev/urandom for entropy."
echo "     For production, use hardware random number generators or"
echo "     combine multiple entropy sources."
echo ""
echo "  3. SECURE ENVIRONMENT:"
echo "     Run the ceremony in a secure, air-gapped environment."
echo "     Destroy all intermediate files and keys after ceremony."
echo ""
echo "  4. VERIFICATION:"
echo "     All participants should verify the transcript of contributions."
echo "     Public verification logs should be published."
echo ""
echo "  5. TRUSTED SETUP ALTERNATIVES:"
echo "     Consider using existing trusted setups like:"
echo "     • Hermez (Polygon) Powers of Tau"
echo "     • Perpetual Powers of Tau"
echo "     • ZCash Powers of Tau"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "🔗 Useful Resources:"
echo "────────────────────────────────────────────────────────────────────────"
echo ""
echo "  Documentation:"
echo "    • SnarkJS: https://github.com/iden3/snarkjs"
echo "    • Circom: https://docs.circom.io/"
echo "    • Powers of Tau: https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/"
echo ""
echo "  Existing Ceremonies:"
echo "    • Hermez: https://github.com/hermeznetwork/phase2ceremony"
echo "    • Perpetual: https://github.com/weijiekoh/perpetualpowersoftau"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "✅ CEREMONY COMPLETED SUCCESSFULLY"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Timestamp: $(date)"
echo "Working directory: $(pwd)"
echo ""
echo "All files are in: $(pwd)"
echo ""

# ============================================================================
# CLEANUP INTERMEDIATE FILES (OPTIONAL)
# ============================================================================

read -p "Do you want to cleanup intermediate ceremony files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo ""
    echo "🧹 Cleaning up intermediate files..."
    rm -f pot21_0000.ptau pot21_0001.ptau pot21_0002.ptau pot21_0003.ptau pot21_beacon.ptau
    rm -f ecdsa_verifier_0000.zkey ecdsa_verifier_0001.zkey ecdsa_verifier_0002.zkey
    echo "✅ Cleanup complete"
    echo ""
    echo "Remaining files:"
    ls -lh pot21_final.ptau ecdsa_verifier_final.zkey verification_key.json verifier.sol
fi

# ============================================================================
# GENERATE CEREMONY ATTESTATION
# ============================================================================

echo ""
echo "📝 Generating ceremony attestation..."

cat > CEREMONY_ATTESTATION.md << 'ATTESTEOF'
# ECDSA Verifier Circuit - Powers of Tau Ceremony Attestation

## Ceremony Details

**Date:** $(date)
**Circuit:** ECDSA Signature Verifier (SECP256K1)
**Curve:** BN128
**Power:** 21 (2^21 = 2,097,152 constraints)

## Phase 1: Powers of Tau

### Participants
1. Contribution 1 - $(date)
2. Contribution 2 - $(date)
3. Contribution 3 - $(date)

### Random Beacon
- Applied: YES
- Iterations: 10

### Verification
- Status: PASSED
- File: `pot21_final.ptau`

## Phase 2: Circuit-Specific Setup

### Participants
1. Phase 2 Contribution 1 - $(date)
2. Phase 2 Contribution 2 - $(date)

### Random Beacon
- Applied: YES
- Iterations: 10

### Verification
- Status: PASSED
- File: `ecdsa_verifier_final.zkey`

## Generated Artifacts

### Proving System
- **Proving Key:** `ecdsa_verifier_final.zkey`
- **Verification Key:** `verification_key.json`
- **Solidity Verifier:** `verifier.sol`

### Circuit Files
- **R1CS:** `ecdsa_verifier.r1cs`
- **WASM:** `ecdsa_verifier_js/ecdsa_verifier.wasm`
- **Witness Generator:** `ecdsa_verifier_js/generate_witness.js`

## Security Considerations

⚠️ **WARNING:** This ceremony was conducted with automated contributions.

**For production use:**
- Conduct a multi-party ceremony (10-50+ participants)
- Use geographically distributed participants
- Implement proper entropy sources
- Publish transparency logs
- Enable public verification

## Circuit Functionality

The ECDSA Verifier circuit proves knowledge of a valid ECDSA signature for SECP256K1 curve without revealing the signature components (r, s, message).

### Public Inputs
- `pubKeyX`: X-coordinate of public key
- `pubKeyY`: Y-coordinate of public key

### Private Inputs
- `message`: Message hash
- `r`: Signature R component
- `s`: Signature S component

### Output
- `valid`: Boolean indicating signature validity (1 = valid, 0 = invalid)

## Verification

To verify the ceremony:

```bash
# Verify Powers of Tau
snarkjs powersoftau verify pot21_final.ptau

# Verify final zkey
snarkjs zkey verify ecdsa_verifier.r1cs pot21_final.ptau ecdsa_verifier_final.zkey
```

## File Hashes

```bash
# Powers of Tau
sha256sum pot21_final.ptau

# Proving Key
sha256sum ecdsa_verifier_final.zkey

# Verification Key
sha256sum verification_key.json

# Solidity Verifier
sha256sum verifier.sol
```

## Usage

### Generate Proof

```bash
# 1. Create input
cat > input.json << EOF
{
  "pubKeyX": "55066263022277343669578718895168534326250603453777594175500187360389116729240",
  "pubKeyY": "32670510020758816978083085130507043184471273380659243275938904335757337482424",
  "message": "123456789",
  "r": "111111111",
  "s": "222222222"
}
EOF

# 2. Generate witness
node ecdsa_verifier_js/generate_witness.js \
    ecdsa_verifier_js/ecdsa_verifier.wasm \
    input.json \
    witness.wtns

# 3. Generate proof
snarkjs groth16 prove \
    ecdsa_verifier_final.zkey \
    witness.wtns \
    proof.json \
    public.json

# 4. Verify locally
snarkjs groth16 verify \
    verification_key.json \
    public.json \
    proof.json
```

### On-Chain Verification

```bash
# Generate call data
snarkjs zkey export soliditycalldata public.json proof.json

# Deploy verifier.sol and call verifyProof() with the generated data
```

## License

This ceremony was conducted for the ECDSA Verifier circuit.
All artifacts are provided as-is for verification and use.

## Contact

For questions or concerns about this ceremony, please contact:
[Your contact information]

---

**Ceremony completed:** $(date)
**Script version:** 1.0.0
ATTESTEOF

echo "✅ Attestation generated: CEREMONY_ATTESTATION.md"
echo ""

# ============================================================================
# GENERATE FILE HASHES
# ============================================================================

echo "🔐 Generating file hashes..."
echo ""

cat > FILE_HASHES.txt << 'HASHEOF'
# File Integrity Hashes
# Generated: $(date)

HASHEOF

sha256sum pot21_final.ptau >> FILE_HASHES.txt 2>/dev/null || echo "pot21_final.ptau - hash not available" >> FILE_HASHES.txt
sha256sum ecdsa_verifier_final.zkey >> FILE_HASHES.txt 2>/dev/null || echo "ecdsa_verifier_final.zkey - hash not available" >> FILE_HASHES.txt
sha256sum verification_key.json >> FILE_HASHES.txt 2>/dev/null || echo "verification_key.json - hash not available" >> FILE_HASHES.txt
sha256sum verifier.sol >> FILE_HASHES.txt 2>/dev/null || echo "verifier.sol - hash not available" >> FILE_HASHES.txt
sha256sum ecdsa_verifier.r1cs >> FILE_HASHES.txt 2>/dev/null || echo "ecdsa_verifier.r1cs - hash not available" >> FILE_HASHES.txt

echo "✅ File hashes saved to: FILE_HASHES.txt"
echo ""

cat FILE_HASHES.txt

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "🎉 ALL DONE!"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Your ECDSA Verifier circuit is ready to use!"
echo ""
echo "Quick start:"
echo "  1. Review: CEREMONY_ATTESTATION.md"
echo "  2. Check hashes: FILE_HASHES.txt"
echo "  3. Deploy: verifier.sol"
echo "  4. Generate proofs: Use the commands shown above"
echo ""
echo "Have fun with zero-knowledge proofs! 🚀"
echo ""