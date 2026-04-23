import os
import secrets
import hashlib
import hmac
import base64
import re
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')

# Secret Key to derive digital signatures for passwords securely
PASSWORD_HMAC_KEY = os.environ.get('PASSWORD_HMAC_KEY', b'my_super_secret_password_signature_key')

jwt = JWTManager(app)

# MongoDB setup
client = MongoClient(app.config['MONGO_URI'])
db = client.lumina_auth
users_collection = db.users

# --- PRE-REGISTRATION CLASSIFICATION ENGINE ---
DISPOSABLE_EMAIL_DOMAINS = ["@10minutemail.com", "@mailinator.com", "@guerrillamail.com", "@temp-mail.org"]
MALICIOUS_IPS = ["192.168.1.99", "10.0.0.50"] # Mock malicious IPs for demonstration
ip_signup_tracker = {} # Mock rate limiting dictionary: { "ip_address": count }

def is_disposable_email(username: str) -> bool:
    for domain in DISPOSABLE_EMAIL_DOMAINS:
        if domain in username.lower():
            return True
    return False

def is_password_strong(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

def is_malicious_ip(ip: str) -> bool:
    return ip in MALICIOUS_IPS

def has_exceeded_signup_rate(ip: str) -> bool:
    MAX_SIGNUPS_PER_IP = 3
    count = ip_signup_tracker.get(ip, 0)
    if count >= MAX_SIGNUPS_PER_IP:
        return True
    ip_signup_tracker[ip] = count + 1
    return False
# ----------------------------------------------

def create_digital_signature(password: str) -> str:
    """Converts a raw password into an HMAC-SHA256 Digital Signature representing it."""
    return hmac.new(PASSWORD_HMAC_KEY, password.encode('utf-8'), hashlib.sha256).hexdigest()

@app.route('/')
def index():
    return send_from_directory('static', 'lumina_auth_frontend.html')

# STANDARD REGISTRATION (Converts Password -> Digital Signature)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_key_hex = data.get('public_key') 
    bot_check = data.get('bot_check')
    user_ip = request.remote_addr

    # --- PHASE 1: PRE-CREATION CLASSIFICATION ---
    # Check 1: The Bot Trap (Honeypot)
    if bot_check:
        return jsonify({'success': False, 'message': 'Malicious activity detected.'}), 403
        
    # Check 2: Disposable/Burner Email Check
    if username and is_disposable_email(username):
        return jsonify({'success': False, 'message': 'Registration from temporary email providers is not allowed.'}), 400
        
    # Check 3: IP Reputation
    if is_malicious_ip(user_ip):
        return jsonify({'success': False, 'message': 'Your network has been flagged for suspicious activity.'}), 403
        
    # Check 4: Rate Limiting
    if has_exceeded_signup_rate(user_ip):
        return jsonify({'success': False, 'message': 'Too many signups from this IP. Try again later.'}), 429
    # ----------------------------------------------

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
    # Check Password Strength
    is_strong, msg = is_password_strong(password)
    if not is_strong:
        return jsonify({'success': False, 'message': msg}), 400
        
    if users_collection.find_one({'username': username}):
        return jsonify({'success': False, 'message': 'Username already exists'}), 409

    # Generate Digital Signature instead of standard password hashing
    digital_signature = create_digital_signature(password)
    
    user_doc = {
        'username': username,
        'digital_signature': digital_signature,
        'public_key': public_key_hex
    }
    users_collection.insert_one(user_doc)
    return jsonify({'success': True, 'message': 'Registration successful.'})


# STANDARD LOGIN (Verifies derived digital signature)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    user = users_collection.find_one({'username': username})
    
    if user:
        # Prevent ZKP users with no digital signature from logging in via standard route
        stored_signature = user.get('digital_signature')
        if not stored_signature:
            return jsonify({'success': False, 'message': 'Account requires Zero-Knowledge Face Auth.'}), 401
            
        computed_signature = create_digital_signature(password)
        
        if computed_signature == stored_signature:
            # Package username and their secure digital signature into JWT directly!
            identity_payload = {
                'username': username,
                'digital_signature': computed_signature
            }
            access_token = create_access_token(identity=identity_payload)
            return jsonify({'success': True, 'message': 'Login successful.', 'access_token': access_token})
            
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

# ZKP CHALLENGE REQUEST (Step 1 of ZKP Auth)
@app.route('/zkp/challenge', methods=['POST'])
def request_challenge():
    data = request.json
    username = data.get('username')
    user = users_collection.find_one({'username': username})
    if not user or not user.get('public_key'):
        return jsonify({'success': False, 'message': 'User not found or ZKP not setup'}), 404
        
    challenge = secrets.token_hex(32)
    users_collection.update_one({'username': username}, {'$set': {'current_challenge': challenge}})
    return jsonify({'success': True, 'challenge': challenge})

# ZKP VERIFY (Step 2 of ZKP Auth)
@app.route('/zkp/verify', methods=['POST'])
def verify_zkp():
    data = request.json
    username = data.get('username')
    signature_hex = data.get('signature')
    
    user = users_collection.find_one({'username': username})
    if not user or 'current_challenge' not in user or not signature_hex:
        return jsonify({'success': False, 'message': 'Invalid ZKP state or missing signature'}), 400
        
    challenge = user['current_challenge']
    public_key_hex = user.get('public_key')
    
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(signature_bytes, challenge.encode())
        
        users_collection.update_one({'username': username}, {'$unset': {'current_challenge': ""}})
        
        # ZKP log in means no password-derived signature
        identity_payload = {'username': username, 'digital_signature': "FaceID-ZeroKnowledge-Proof"}
        access_token = create_access_token(identity=identity_payload)
        return jsonify({'success': True, 'message': 'ZKP Login successful.', 'access_token': access_token})
        
    except (InvalidSignature, ValueError):
        return jsonify({'success': False, 'message': 'ZKP Verification failed.'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    identity = get_jwt_identity()
    return jsonify({
        'success': True, 
        'username': identity.get('username'),
        'digital_signature': identity.get('digital_signature')
    })

# === HACKER MODULE ROUTES ===
@app.route('/hacker/generate', methods=['POST'])
def hacker_generate():
    data = request.json
    word = data.get('word', '')
    if not word:
        return jsonify({'success': False, 'signature': ''})
    sig = create_digital_signature(word)
    return jsonify({'success': True, 'signature': sig})

@app.route('/hacker/attack', methods=['POST'])
def hacker_attack():
    data = request.json
    target_signature = data.get('signature', '')
    actual_word = data.get('word', '')
    
    if not target_signature:
        return jsonify({'success': False, 'message': 'No signature provided'})

    logs = []
    import string
    import random
    
    # We define crackable bounds for our simulated supercomputer.
    # Short words or purely numeric words are crackable. Long complex ones are unbreakable.
    is_crackable = False
    if len(actual_word) <= 8 or actual_word.isdigit() or actual_word.isalpha():
        is_crackable = True

    # Generate 50-70 realistic looking brute force attempts based on the word's structure
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    for k in range(random.randint(50, 75)):
        random_attempt = "".join(random.choice(chars) for _ in range(len(actual_word) if actual_word else 6))
        logs.append(random_attempt)
        
    if is_crackable and actual_word:
        # Add the actual word at the end to simulate hitting the exact hash permutation
        logs.append(actual_word)
        return jsonify({
            'success': True,
            'status': 'CRACKED',
            'word': actual_word,
            'logs': logs
        })
    else:
        # Simulate hitting limit
        return jsonify({
            'success': True,
            'status': 'FAILED',
            'word': None,
            'logs': logs
        })

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({'success': True, 'message': 'Logout successful'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)