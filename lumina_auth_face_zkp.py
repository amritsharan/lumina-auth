import cv2
import face_recognition
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SERVER_URL = "http://127.0.0.1:5000"

def capture_face():
    video_capture = cv2.VideoCapture(0)
    print("Press 'q' to capture your face.")
    face_image = None
    while True:
        ret, frame = video_capture.read()
        if not ret:
            break
        cv2.imshow('Webcam - Face Capture', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            face_image = frame
            break
    video_capture.release()
    cv2.destroyAllWindows()
    return face_image

def extract_features(image):
    face_locations = face_recognition.face_locations(image)
    if not face_locations:
        return None
    face_encodings = face_recognition.face_encodings(image, face_locations)
    return face_encodings[0] if len(face_encodings) > 0 else None

def generate_keypair_from_face(features):
    # Hash facial features to 32 bytes to form a stable seed
    seed = hashlib.sha256(features.tobytes()).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_key.hex(), private_key

def zkp_register(username, password, public_key_hex):
    # Register with standard password, and attach our Public Key for future ZKP logins
    data = {
        "username": username,
        "password": password,
        "public_key": public_key_hex
    }
    resp = requests.post(f"{SERVER_URL}/register", json=data)
    return resp.json()

def zkp_login(username, private_key):
    # Step 1: Request Challenge
    resp = requests.post(f"{SERVER_URL}/zkp/challenge", json={"username": username})
    if resp.status_code != 200:
        return resp.json()
    challenge = resp.json().get('challenge')
    
    # Step 2: Sign Challenge Locally
    signature = private_key.sign(challenge.encode())
    
    # Step 3: Verify at Server
    resp = requests.post(f"{SERVER_URL}/zkp/verify", json={
        "username": username,
        "signature": signature.hex()
    })
    return resp.json()

if __name__ == "__main__":
    print("Lumina-Auth Zero-Knowledge Face Client")
    print("1. Register Face (Requires Username & Backup Password)")
    print("2. Login with Face (Zero Knowledge / Challenge Response)")
    choice = input("Enter choice (1/2): ")
    
    username = input("Enter username: ")
    
    image = capture_face()
    if image is None:
        print("Camera access failed.")
        exit(1)
        
    features = extract_features(image)
    if features is None:
        print("Face not detected. Aborting.")
        exit(1)
        
    public_key_hex, private_key = generate_keypair_from_face(features)
    
    if choice == "1":
        password = input("Enter a strong backup password: ")
        res = zkp_register(username, password, public_key_hex)
        print("Registration Result:", res)
    elif choice == "2":
        print("Attempting Zero-Knowledge Proof login...")
        res = zkp_login(username, private_key)
        print("Login Result:", res)
        # Try a protected route
        if res.get('success'):
            jwt_token = res.get('access_token')
            prot_res = requests.get(f"{SERVER_URL}/protected", headers={"Authorization": f"Bearer {jwt_token}"})
            print("Protected Route Access:", prot_res.json())
    else:
        print("Invalid choice")
