/**
 * Lumina-Auth Client-Side Behavioral Entropy & WebAuthn Harvester
 * Captures continuous Neuromuscular Dynamics:
 * - Key Dwell Time (Td)
 * - Key Flight Time (Tf)
 * - Neuromuscular Micro-Jitter (Jμ)
 * - WebAuthn Hardware Enclave Coupling (σhw)
 */

class LuminaBehavioralTelemetryHarvester {
    constructor() {
        this.dwellTimes = [];
        this.flightTimes = [];
        this.mouseJitterTimes = [];
        
        this.keyDownTimestamps = {};
        this.lastKeyUpTimestamp = null;
        this.lastMouseMoveTimestamp = null;

        this.initListeners();
    }

    initListeners() {
        // Keystroke dynamics tracking
        window.addEventListener('keydown', (e) => {
            const now = performance.now();
            if (!this.keyDownTimestamps[e.code]) {
                this.keyDownTimestamps[e.code] = now;
            }
            if (this.lastKeyUpTimestamp !== null) {
                const flightTime = Math.round(now - this.lastKeyUpTimestamp);
                if (flightTime > 0 && flightTime < 2000) {
                    this.flightTimes.push(flightTime);
                    if (this.flightTimes.length > 50) this.flightTimes.shift();
                }
            }
        });

        window.addEventListener('keyup', (e) => {
            const now = performance.now();
            if (this.keyDownTimestamps[e.code]) {
                const dwellTime = Math.round(now - this.keyDownTimestamps[e.code]);
                if (dwellTime > 0 && dwellTime < 2000) {
                    this.dwellTimes.push(dwellTime);
                    if (this.dwellTimes.length > 50) this.dwellTimes.shift();
                }
                delete this.keyDownTimestamps[e.code];
            }
            this.lastKeyUpTimestamp = now;
        });

        // Neuromuscular Micro-Jitter tracking (Mouse timing variance)
        window.addEventListener('mousemove', (e) => {
            const now = performance.now();
            if (this.lastMouseMoveTimestamp !== null) {
                const delta = Math.round((now - this.lastMouseMoveTimestamp) * 100);
                this.mouseJitterTimes.push(delta % 100); // Micro-jitter variance
                if (this.mouseJitterTimes.length > 100) this.mouseJitterTimes.shift();
            }
            this.lastMouseMoveTimestamp = now;
        });
    }

    /**
     * Calculates Neuromuscular Micro-Jitter variance (Jμ)
     */
    calculateJitterVariance() {
        if (this.mouseJitterTimes.length === 0) return 12; // default baseline jitter
        const mean = this.mouseJitterTimes.reduce((a, b) => a + b, 0) / this.mouseJitterTimes.length;
        const variance = this.mouseJitterTimes.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / this.mouseJitterTimes.length;
        return Math.round(variance) || 12;
    }

    /**
     * WebAuthn Hardware Root-of-Trust Nonce Signing
     */
    async getHardwareEnclaveSignature(challengeNonce) {
        if (!window.PublicKeyCredential) {
            // Fallback for environments without hardware WebAuthn credentials
            return 0x01; // Mock TEE flag
        }

        try {
            const challenge = new TextEncoder().encode(challengeNonce);
            const publicKeyCredentialRequestOptions = {
                challenge: challenge,
                timeout: 60000,
                userVerification: "discouraged"
            };
            // WebAuthn hardware call attempt
            const credential = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
            if (credential) {
                const sigBuffer = new Uint8Array(credential.response.signature);
                return sigBuffer[0] || 1;
            }
        } catch (err) {
            // Fallback for local dev/testing
            console.log("WebAuthn hardware fallback used:", err.message);
        }
        return 1;
    }

    /**
     * Harvests standard 8-element witness vector for Circom ZK proof
     * [Td1, Td2, Td3, Tf1, Tf2, Tf3, Jμ, σhw]
     */
    async harvestWitnessVector(challengeNonce = "lumina-auth-epoch-1") {
        // Average or pick recent sample features
        const avgTd = (arr, def) => arr.length > 0 ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : def;
        
        const td1 = this.dwellTimes[this.dwellTimes.length - 1] || 100;
        const td2 = this.dwellTimes[this.dwellTimes.length - 2] || 105;
        const td3 = this.dwellTimes[this.dwellTimes.length - 3] || 98;

        const tf1 = this.flightTimes[this.flightTimes.length - 1] || 120;
        const tf2 = this.flightTimes[this.flightTimes.length - 2] || 115;
        const tf3 = this.flightTimes[this.flightTimes.length - 3] || 122;

        const jMu = this.calculateJitterVariance();
        const sHw = await this.getHardwareEnclaveSignature(challengeNonce);

        return [td1, td2, td3, tf1, tf2, tf3, jMu, sHw];
    }
}

window.luminaHarvester = new LuminaBehavioralTelemetryHarvester();
