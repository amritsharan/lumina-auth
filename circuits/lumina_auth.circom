pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * Lumina-Auth Zero-Knowledge Identity & Behavioral Liveness Circuit
 * Evaluates BN254 Rank-1 Constraint System (R1CS) for:
 * 1. Bounded Euclidean Distance constraint between private witness telemetry and baseline template.
 * 2. Poseidon Algebraic Hash Commitment verification.
 */
template LuminaAuthVerifier(N_SAMPLES) {
    // ------------------------------------------------------------------------
    // SIGNALS
    // ------------------------------------------------------------------------
    
    // Private witness telemetry: [Td1..Tdn, Tf1..Tfn, Jμ1..Jμk, σhw]
    signal input witness[N_SAMPLES];
    
    // Public inputs
    signal input PoseidonCommitment;
    signal input salt;
    signal input baseline[N_SAMPLES];
    signal input deltaMax;

    // Output signal
    signal output isValid;

    // ------------------------------------------------------------------------
    // 1. POSEIDON HASH COMMITMENT CONSTRAINT
    // ------------------------------------------------------------------------
    // Inputs to Poseidon: witness array elements + salt as final element
    component poseidonHasher = Poseidon(N_SAMPLES + 1);
    for (var i = 0; i < N_SAMPLES; i++) {
        poseidonHasher.inputs[i] <== witness[i];
    }
    poseidonHasher.inputs[N_SAMPLES] <== salt;

    // Enforce hash commitment match
    poseidonHasher.out === PoseidonCommitment;

    // ------------------------------------------------------------------------
    // 2. BOUNDED EUCLIDEAN DISTANCE CONSTRAINT
    // ------------------------------------------------------------------------
    // Calculate sum of squared differences: Σ (witness[i] - baseline[i])^2
    signal diff[N_SAMPLES];
    signal diffSq[N_SAMPLES];
    
    var sum = 0;
    for (var i = 0; i < N_SAMPLES; i++) {
        diff[i] <== witness[i] - baseline[i];
        diffSq[i] <== diff[i] * diff[i];
    }

    // Accumulate squared distances using array signals
    signal distAcc[N_SAMPLES + 1];
    distAcc[0] <== 0;
    for (var i = 0; i < N_SAMPLES; i++) {
        distAcc[i + 1] <== distAcc[i] + diffSq[i];
    }

    // Enforce distAcc[N_SAMPLES] <= deltaMax (using 64-bit LessThan comparison)
    // LessThan(64) returns 1 if in[0] < in[1], so we check distAcc[N_SAMPLES] < deltaMax + 1
    component comp = LessThan(64);
    comp.in[0] <== distAcc[N_SAMPLES];
    comp.in[1] <== deltaMax + 1;

    // Constraint: Distance must be within threshold
    comp.out === 1;

    isValid <== comp.out;
}

// Instantiate circuit for 8 telemetry sample features (e.g. 3 Td, 3 Tf, 1 Jμ, 1 σhw)
component main {public [PoseidonCommitment, salt, baseline, deltaMax]} = LuminaAuthVerifier(8);
