# Lumina-Auth: Post-Quantum Secure Enterprise Authentication

Lumina-Auth is a state-of-the-art authentication system designed to bridge modern usability with cryptographic resilience against classical and future quantum threats. 

---

## Key Features

1. **Standard Auth with Multi-Step Mobile OTP**
   - Traditional login and registration are protected by a stateful multi-step wizard.
   - Credentials (Username & Password) are validated before requesting phone verification.
   - Dynamically supports dialing codes for all 195+ countries in the world.
   - Integrates a dual SMS gateway: **Twilio** (primary) and **Textbelt** (fallback), with standard console print simulation for local development.

2. **Zero-Knowledge Face Auth (ZKP)**
   - Allows passwordless authentication using computer vision facial features.
   - Computes a stable cryptographic key pair from facial encodings.
   - Uses Ed25519 signatures to sign server-sent challenges, verifying identity without sending any biometric data to the server.

3. **Post-Quantum Cryptographic Resilience (PQC)**
   - Plaintext passwords are not hashed with weak standard algorithms. Instead, the backend derives a **HMAC-SHA256 Digital Signature** using a server-side secret key.
   - Achieves 128-bit PQC strength, mathematically secure against Grover's Quantum search algorithm and Shor's factorization algorithm.

---

## Tech Stack

- **Backend**: Python, Flask, Flask-CORS, Flask-JWT-Extended
- **Database**: MongoDB (user documents, OTP sessions)
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (glassmorphic dark design)
- **Biometrics & Crypto**: OpenCV, `face_recognition`, `cryptography`
- **SMS Gateways**: Twilio API, Textbelt API

---

## Installation & Setup

### Prerequisites
Make sure you have Python 3.10+ and a local MongoDB instance running.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/amritsharan/lumina-auth.git
   cd "Lumina auth"
   ```

2. **Set Up the Virtual Environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate     # On Windows
   source .venv/bin/activate  # On Linux/macOS
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**
   Copy the environment variables template and configure your values (such as Twilio keys for real SMS):
   ```bash
   copy .env.template .env
   ```
   Open the `.env` file and insert your Twilio SID, Auth Token, and Twilio phone number.

---

## Running the Application

### 1. Launch the Server
Ensure MongoDB is running, then start the Flask server:
```bash
python lumina_auth_server.py
```
The server will start at [http://127.0.0.1:5000/](http://127.0.0.1:5000/). Open this address in your web browser to access the premium glassmorphic UI.

### 2. Run the Standard CLI Client
You can also use the interactive terminal client to register or log in:
```bash
python lumina_auth_client.py
```

### 3. Run the Zero-Knowledge Face Auth Client
To test passwordless biometric challenge-response login:
```bash
python lumina_auth_face_zkp.py
```
*Note: This script requires a webcam to capture your face and build your biometric key pair.*
