import requests

SERVER_URL = "http://127.0.0.1:5000"

def register_account(username, password, phone=None):
    payload = {
        "username": username,
        "password": password
    }
    if phone:
        payload["phone"] = phone
    resp = requests.post(f"{SERVER_URL}/register", json=payload)
    return resp.json()

def login_account(username, password):
    resp = requests.post(f"{SERVER_URL}/login", json={
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

def test_direct_sms(phone):
    resp = requests.post(f"{SERVER_URL}/otp/send", json={"phone": phone})
    return resp.json()

def access_protected(token):
    resp = requests.get(f"{SERVER_URL}/protected", headers={"Authorization": f"Bearer {token}"})
    return resp.json()

if __name__ == "__main__":
    print("=" * 55)
    print("              Lumina-Auth CLI Client")
    print("=" * 55)
    print("1. Register Account (Username, Password & Mobile Number)")
    print("2. Login (Username & Password)")
    print("3. Login with Mobile OTP (2FA Verification)")
    print("4. Direct SMS / OTP Delivery Test")
    print("=" * 55)
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice == "1":
        print("\n--- Account Registration ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        phone = input("Enter mobile number with country code (e.g. +919876543210 or +1234567890): ").strip()
        
        print("\nCreating account and linking mobile number...")
        res = register_account(username, password, phone)
        if res.get("success"):
            print("\n[SUCCESS]", res.get("message", "Account registered successfully!"))
            if res.get("phone"):
                print(f"Linked Mobile Number: {res.get('phone')}")
            token = res.get("access_token")
            print("\nJWT Access Token:", token)
            print("\nAccessing protected route with token:")
            print(access_protected(token))
        else:
            print("\n[FAILED] Registration failed:", res.get("message"))
            
    elif choice == "2":
        print("\n--- Standard Login ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        print("\nAuthenticating...")
        res = login_account(username, password)
        if res.get("success"):
            print("\n[SUCCESS]", res.get("message", "Login successful!"))
            token = res.get("access_token")
            print("JWT Access Token:", token)
            print("\nAccessing protected route with token:")
            print(access_protected(token))
        else:
            print("\n[FAILED] Login failed:", res.get("message"))
            
    elif choice == "3":
        print("\n--- Mobile OTP Authentication (2FA) ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        phone = input("Enter registered mobile number (e.g. +919876543210): ").strip()
        
        print("\nStep 1: Requesting OTP from server...")
        send_res = send_auth_otp(username, password, phone, "login")
        if not send_res.get("success"):
            print("[FAILED] Could not send OTP:", send_res.get("message"))
            exit(1)
            
        gateway = send_res.get("gateway", "unknown")
        print(f"[STATUS] OTP dispatched via gateway: {gateway.upper()}")
        if send_res.get("dev_otp"):
            print(f"[DEBUG HINT] Local OTP: {send_res.get('dev_otp')}")
            
        otp = input("\nEnter the 6-digit OTP received: ").strip()
        print("Step 2: Verifying OTP...")
        verify_res = verify_auth_otp(username, password, phone, otp, "login")
        if verify_res.get("success"):
            print("\n[SUCCESS] OTP Verified! Authentication Complete.")
            token = verify_res.get("access_token")
            print("JWT Access Token:", token)
            print("\nAccessing protected route with token:")
            print(access_protected(token))
        else:
            print("\n[FAILED] OTP Verification failed:", verify_res.get("message"))
            
    elif choice == "4":
        print("\n--- Direct SMS / OTP Delivery Test ---")
        phone = input("Enter recipient phone number with country code (e.g. +919876543210): ").strip()
        print(f"\nSending test OTP SMS to {phone}...")
        res = test_direct_sms(phone)
        if res.get("success"):
            print(f"[SUCCESS] OTP dispatched successfully! (Gateway: {res.get('gateway', 'sms')})")
        else:
            print(f"[STATUS] Server response: {res.get('message')}")
        print("Check the server terminal log to see gateway delivery details / error messages.")
    else:
        print("Invalid choice.")
