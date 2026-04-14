import os
import secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')

jwt = JWTManager(app)

# MongoDB setup
client = MongoClient(app.config['MONGO_URI'])
db = client.lumina_auth
users_collection = db.users

@app.route('/')
def index():
    return send_from_directory('static', 'lumina_auth_frontend.html')

# STANDARD REGISTRATION
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_key_hex = data.get('public_key') # Optional: for ZKP login

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    if users_collection.find_one({'username': username}):
        return jsonify({'success': False, 'message': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password)
    
    user_doc = {
        'username': username,
        'password': hashed_password,
        'public_key': public_key_hex # hex string of Ed25519 public key if registered via ZKP
    }
    users_collection.insert_one(user_doc)
    return jsonify({'success': True, 'message': 'Registration successful.'})


# STANDARD LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    user = users_collection.find_one({'username': username})
    if user and check_password_hash(user.get('password', ''), password):
        access_token = create_access_token(identity=username)
        return jsonify({'success': True, 'message': 'Login successful.', 'access_token': access_token})
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

# ZKP CHALLENGE REQUEST (Step 1 of ZKP Auth)
@app.route('/zkp/challenge', methods=['POST'])
def request_challenge():
    data = request.json
    username = data.get('username')
    user = users_collection.find_one({'username': username})
    if not user or not user.get('public_key'):
        return jsonify({'success': False, 'message': 'User not found or ZKP not setup'}), 404
        
    # Generate a random 32-byte challenge
    challenge = secrets.token_hex(32)
    
    # Store challenge temporarily
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
        # Load public key
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Verify signature over the challenge
        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(signature_bytes, challenge.encode())
        
        # Success! Clear challenge and issue JWT
        users_collection.update_one({'username': username}, {'$unset': {'current_challenge': ""}})
        access_token = create_access_token(identity=username)
        return jsonify({'success': True, 'message': 'ZKP Login successful.', 'access_token': access_token})
        
    except (InvalidSignature, ValueError) as e:
        return jsonify({'success': False, 'message': 'ZKP Verification failed.'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'success': True, 'message': f'Hello {current_user}, you are securely authenticated!'})

@app.route('/logout', methods=['POST'])
def logout():
    # To truly logout a JWT you need a token blocklist. 
    # For now, we trust the client to delete the token.
    return jsonify({'success': True, 'message': 'Logout successful'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)