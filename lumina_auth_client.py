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
    elif choice == "2":
        result = login(username, password)
        print("Login result:", result)
        if result.get("success"):
            print("Access Token Generated!")
            token = result.get("access_token")
            # Automatically try accessing protected route
            print("Trying to access protected route with token:")
            prot = access_protected(token)
            print(prot)
    else:
        print("Invalid choice.")
