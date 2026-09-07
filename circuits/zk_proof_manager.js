const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

class LuminaZKProofManager {
    constructor() {
        this.poseidon = null;
    }

    async init() {
        if (!this.poseidon) {
            this.poseidon = await buildPoseidon();
        }
    }

    /**
     * Calculates Poseidon hash for witness vector + salt over BN254 scalar field
     * @param {Array<number|bigint>} witness Telemetry sample vector
     * @param {number|bigint} salt Cryptographic salt
     * @returns {string} Hex string of Poseidon commitment hash
     */
    calculatePoseidonCommitment(witness, salt) {
        if (!this.poseidon) throw new Error("Poseidon hasher not initialized. Call init() first.");
        const inputs = [...witness.map(x => BigInt(x)), BigInt(salt)];
        const hash = this.poseidon(inputs);
        return this.poseidon.F.toString(hash);
    }

    /**
     * Calculates Euclidean distance sum: Σ (witness[i] - baseline[i])^2
     * @param {Array<number>} witness 
     * @param {Array<number>} baseline 
     * @returns {number}
     */
    calculateEuclideanDistanceSq(witness, baseline) {
        let sum = 0;
        for (let i = 0; i < witness.length; i++) {
            const diff = witness[i] - baseline[i];
            sum += diff * diff;
        }
        return sum;
    }

    /**
     * Constructs witness input object for Circom / Groth16 prover
     * @param {Array<number>} witness 
     * @param {Array<number>} baseline 
     * @param {number} deltaMax 
     * @param {number|bigint} salt 
     */
    buildCircuitInput(witness, baseline, deltaMax, salt) {
        const commitment = this.calculatePoseidonCommitment(witness, salt);
        return {
            witness: witness.map(x => x.toString()),
            baseline: baseline.map(x => x.toString()),
            PoseidonCommitment: commitment,
            salt: salt.toString(),
            deltaMax: deltaMax.toString()
        };
    }
}

module.exports = LuminaZKProofManager;

// Quick CLI runner if executed directly
if (require.main === module) {
    (async () => {
        const manager = new LuminaZKProofManager();
        await manager.init();

        const witness = [100, 105, 98, 120, 115, 122, 12, 1]; // [Td1..3, Tf1..3, Jμ, σhw]
        const baseline = [102, 104, 100, 118, 116, 120, 10, 1];
        const salt = 123456789;
        const deltaMax = 50; // Threshold

        const distSq = manager.calculateEuclideanDistanceSq(witness, baseline);
        const commitment = manager.calculatePoseidonCommitment(witness, salt);

        console.log("=== Lumina-Auth ZK Witness Test ===");
        console.log("Calculated Euclidean Distance Sq:", distSq, "(Threshold:", deltaMax, ")");
        console.log("Calculated Poseidon Commitment:", commitment);
        console.log("Within Liveness Threshold?", distSq <= deltaMax ? "YES (VALID PROOF)" : "NO (ANOMALY DETECTED)");
    })();
}
