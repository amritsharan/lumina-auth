import requests

SERVER_URL = "http://127.0.0.1:5000"

def register(username, password):
    resp = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password})
    return resp.json()

def login(username, password):
    resp = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
    return resp.json()

def access_protected(token):
    resp = requests.get(f"{SERVER_URL}/protected", headers={"Authorization": f"Bearer {token}"})
    return resp.json()

def upload_file(token, filepath):
    with open(filepath, 'rb') as f:
        files = {'file': f}
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.post(f"{SERVER_URL}/upload", headers=headers, files=files)
    return resp.json()

def download_file(token, file_id, save_path):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{SERVER_URL}/download/{file_id}", headers=headers)
    if resp.status_code == 200:
        with open(save_path, 'wb') as f:
            f.write(resp.content)
        return {"success": True, "message": f"Saved decrypted to {save_path}"}
    try:
        return resp.json()
    except:
        return {"success": False, "message": f"HTTP {resp.status_code}"}

def send_otp(phone):
    resp = requests.post(f"{SERVER_URL}/otp/send", json={"phone": phone})
    return resp.json()

def verify_otp(phone, otp):
    resp = requests.post(f"{SERVER_URL}/otp/verify", json={"phone": phone, "otp": otp})
    return resp.json()

if __name__ == "__main__":
    print("Lumina-Auth Standard JWT & OTP Client")
    print("1. Register (Password)")
    print("2. Login (Password)")
    print("3. Send OTP (Mobile)")
    print("4. Verify OTP & Login (Mobile)")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice in ("1", "2"):
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        if choice == "1":
            result = register(username, password)
            print("Register result:", result)
            if result.get("success"):
                print("Registration successful! Automatically logging in...")
                choice = "2" # Flow right into login
                
        if choice == "2":
            result = login(username, password)
            print("Login result:", result)
            if result.get("success"):
                print("Access Token Generated!")
                token = result.get("access_token")
                print("Trying to access protected route with token:")
                prot = access_protected(token)
                print(prot)
    elif choice == "3":
        phone = input("Enter mobile number (e.g. +1234567890): ").strip()
        result = send_otp(phone)
        print("Send OTP result:", result)
    elif choice == "4":
        phone = input("Enter mobile number (e.g. +1234567890): ").strip()
        otp = input("Enter 6-digit OTP code: ").strip()
        result = verify_otp(phone, otp)
        print("Verify OTP result:", result)
        if result.get("success"):
            print("Access Token Generated!")
            token = result.get("access_token")
            print("Trying to access protected route with token:")
            prot = access_protected(token)
            print(prot)
    else:
        print("Invalid choice.")
