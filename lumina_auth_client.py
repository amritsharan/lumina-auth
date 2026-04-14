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

if __name__ == "__main__":
    print("Lumina-Auth Standard JWT Client")
    print("1. Register")
    print("2. Login")
    choice = input("Enter 1 or 2: ")
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
    elif choice != "1" and choice != "2":
        print("Invalid choice.")
