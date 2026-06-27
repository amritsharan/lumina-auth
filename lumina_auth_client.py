import requests

SERVER_URL = "http://127.0.0.1:5000"

def validate_credentials(username, password):
    resp = requests.post(f"{SERVER_URL}/auth/validate-credentials", json={
        "username": username,
        "password": password
    })
    return resp.json()

def send_auth_otp(username, password, phone, action):
    resp = requests.post(f"{SERVER_URL}/auth/send-otp", json={
        "username": username,
        "password": password,
        "phone": phone,
        "action": action
    })
    return resp.json()

def verify_auth_otp(username, password, phone, otp, action):
    resp = requests.post(f"{SERVER_URL}/auth/verify-otp", json={
        "username": username,
        "password": password,
        "phone": phone,
        "otp": otp,
        "action": action
    })
    return resp.json()

def access_protected(token):
    resp = requests.get(f"{SERVER_URL}/protected", headers={"Authorization": f"Bearer {token}"})
    return resp.json()

if __name__ == "__main__":
    print("Lumina-Auth Standard JWT & OTP Client")
    print("1. Register (Standard Auth with Mobile OTP)")
    print("2. Login (Standard Auth with Mobile OTP)")
    
    choice = input("Enter choice (1-2): ").strip()
    
    if choice in ("1", "2"):
        action = "register" if choice == "1" else "login"
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        # Step 1: Validate credentials
        print(f"\nStep 1: Validating credentials for {action}...")
        val_res = validate_credentials(username, password)
        if not val_res.get("success"):
            print("Validation failed:", val_res.get("message"))
            exit(1)
            
        print("Credentials valid!")
        
        # Step 2: Request mobile number and trigger OTP
        phone = input("\nEnter mobile number with country code (e.g. +1234567890): ").strip()
        print("Step 2: Sending OTP to phone number...")
        send_res = send_auth_otp(username, password, phone, action)
        if not send_res.get("success"):
            print("Failed to send OTP:", send_res.get("message"))
            exit(1)
            
        # OTP code display removed for security
            
        print("OTP triggered successfully via SMS!")
        
        # Step 3: Enter and verify OTP
        otp = input("\nEnter 6-digit OTP code received: ").strip()
        print("Step 3: Verifying OTP...")
        verify_res = verify_auth_otp(username, password, phone, otp, action)
        if not verify_res.get("success"):
            print("Verification failed:", verify_res.get("message"))
            exit(1)
            
        print("\nAuthentication successful!")
        token = verify_res.get("access_token")
        print("Access Token:", token)
        
        print("\nAccessing protected route with token:")
        prot = access_protected(token)
        print(prot)
    else:
        print("Invalid choice.")
