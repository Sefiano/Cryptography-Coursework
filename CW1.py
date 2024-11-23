import os
import json
import shutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import time

# Global variables for storing user data
users = {}
current_user = None
failed_attempts = {}  # Track failed login attempts
MAX_FAILED_ATTEMPTS = 3  # Maximum allowed failed attempts
FILE_NAME_LIMIT = 255  # Maximum file name length
FILE_CONTENT_LIMIT = 1024 * 1024  # Maximum file content size (1 MB)
ADMIN_KEY = get_random_bytes(16)  # AES key for admin log encryption

def initialize_program():
    """Initialize program directories and files"""
    if not os.path.exists("user_data"):
        os.makedirs("user_data")
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            global users
            users = json.load(f)

def save_users():
    """Save user data to file"""
    with open("users.json", "w") as f:
        json.dump(users, f)

def log_action(action):
    """Log user actions in a plain text log file"""
    log_file_path = "user_data/admin_log.txt"  # Changed to plain text file
    log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {current_user}: {action}\n"  # Updated log format
    
    with open(log_file_path, "a") as log_file:
        log_file.write(log_entry)  # Write log entry as plain text

def generate_user_keys():
    """Generate RSA key pair for new user"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_password(password, public_key):
    """Encrypt password using RSA"""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return b64encode(cipher.encrypt(password.encode())).decode()

def decrypt_password(encrypted_password, private_key):
    """Decrypt password using RSA"""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(b64decode(encrypted_password)).decode()

def check_password_complexity(password):
    """Check if password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    
    return True, "Password meets complexity requirements"

def register_user(username, password):
    """Register a new user"""
    if username in users:
        return False, "Username already exists"
    
    # Add password complexity check
    is_valid, message = check_password_complexity(password)
    if not is_valid:
        return False, message
    
    private_key, public_key = generate_user_keys()
    encrypted_password = encrypt_password(password, public_key)
    
    users[username] = {
        "password": encrypted_password,
        "private_key": private_key.decode(),
        "public_key": public_key.decode()
    }
    
    user_dir = f"user_data/{username}"
    os.makedirs(user_dir, exist_ok=True)
    
    save_users()
    log_action(f"User registered: {username}")  # Log registration action
    return True, "Registration successful"

def login_user(username, password):
    """Login user with credentials"""
    if username not in users:
        return False, "User not found"
    
    # Check if the account is temporarily disabled
    if username in failed_attempts and failed_attempts[username] >= MAX_FAILED_ATTEMPTS:
        return False, "Account temporarily disabled due to multiple failed login attempts"
    
    user = users[username]
    try:
        decrypted_password = decrypt_password(user["password"], user["private_key"].encode())
        if password == decrypted_password:
            global current_user
            current_user = username
            failed_attempts[username] = 0  # Reset failed attempts on successful login
            log_action(f"User logged in: {username}")  # Log login action
            return True, "Login successful"
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1  # Increment failed attempts
            return False, "Invalid password"
    except:
        return False, "Login failed"

def encrypt_file_content(content, key):
    """Encrypt file content using AES"""
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(content.encode())
    return b64encode(nonce + tag + ciphertext).decode()

def decrypt_file_content(encrypted_content, key):
    """Decrypt file content using AES"""
    try:
        data = b64decode(encrypted_content)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except:
        return None

def create_file(filename, content):
    """Create new encrypted file"""
    if not current_user:
        return False, "Not logged in"
    
    # Check file name length
    if len(filename) > FILE_NAME_LIMIT:
        return False, f"File name must be less than {FILE_NAME_LIMIT} characters"
    
    # Check file content size
    if len(content) > FILE_CONTENT_LIMIT:
        return False, f"File content must be less than {FILE_CONTENT_LIMIT} bytes"
    
    file_path = f"user_data/{current_user}/{filename}"
    if os.path.exists(file_path):
        return False, "File already exists"
    
    try:
        # Generate AES key for file encryption
        file_key = get_random_bytes(16)
        encrypted_content = encrypt_file_content(content, file_key)
        
        # Encrypt AES key with user's RSA public key
        rsa_key = RSA.import_key(users[current_user]["public_key"].encode())
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_file_key = b64encode(cipher.encrypt(file_key)).decode()
        
        file_data = {
            "content": encrypted_content,
            "key": encrypted_file_key
        }
        
        with open(file_path, "w") as f:
            json.dump(file_data, f)
        
        log_action(f"File created: {filename} by {current_user}")  # Log file creation action
        return True, "File created successfully"
    except:
        return False, "Failed to create file"

def read_file(filename):
    """Read encrypted file"""
    if not current_user:
        return False, "Not logged in"
    
    file_path = f"user_data/{current_user}/{filename}"
    if not os.path.exists(file_path):
        return False, "File not found"
    
    try:
        with open(file_path, "r") as f:
            file_data = json.load(f)
        
        # Decrypt file key using user's RSA private key
        rsa_key = RSA.import_key(users[current_user]["private_key"].encode())
        cipher = PKCS1_OAEP.new(rsa_key)
        file_key = cipher.decrypt(b64decode(file_data["key"]))
        
        # Decrypt file content using AES key
        content = decrypt_file_content(file_data["content"], file_key)
        if content is None:
            return False, "Failed to decrypt file"
        
        return True, content
    except:
        return False, "Failed to read file"

def append_to_file(filename, new_content):
    """Append content to encrypted file"""
    success, result = read_file(filename)
    if not success:
        return success, result
    
    updated_content = result + new_content
    return create_file(filename, updated_content)

def delete_file(filename):
    """Delete encrypted file"""
    if not current_user:
        return False, "Not logged in"
    
    file_path = f"user_data/{current_user}/{filename}"
    if not os.path.exists(file_path):
        return False, "File not found"
    
    try:
        os.remove(file_path)
        log_action(f"File deleted: {filename} by {current_user}")  # Log file deletion action
        return True, "File deleted successfully"
    except:
        return False, "Failed to delete file"

def list_files():
    """List all files for current user"""
    if not current_user:
        return False, "Not logged in"
    
    user_dir = f"user_data/{current_user}"
    try:
        files = os.listdir(user_dir)
        return True, files
    except:
        return False, "Failed to list files"

def main():
    initialize_program()
    
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == "1":
            username = input("Enter username: ")
            print("\nPassword requirements:")
            print("- At least 8 characters long")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one special character")
            password = input("Enter password: ")
            success, message = register_user(username, password)
            print(message)
        
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, message = login_user(username, password)
            print(message)
            
            if success:
                while True:
                    print("\n1. List Files")
                    print("2. View File")
                    print("3. Create New File")
                    print("4. Append to File")
                    print("5. Delete File")
                    print("6. Logout")
                    
                    user_choice = input("Enter your choice (1-6): ")
                    
                    if user_choice == "1":
                        success, files = list_files()
                        if success:
                            print("\nYour files:")
                            for file in files:
                                print(file)
                        else:
                            print(files)
                    
                    elif user_choice == "2":
                        filename = input("Enter filename: ")
                        success, content = read_file(filename)
                        if success:
                            print("\nFile content:")
                            print(content)
                        else:
                            print(content)
                    
                    elif user_choice == "3":
                        filename = input("Enter filename: ")
                        content = input("Enter content: ")
                        success, message = create_file(filename, content)
                        print(message)
                    
                    elif user_choice == "4":
                        filename = input("Enter filename: ")
                        content = input("Enter content to append: ")
                        success, message = append_to_file(filename, content)
                        print(message)
                    
                    elif user_choice == "5":
                        filename = input("Enter filename: ")
                        success, message = delete_file(filename)
                        print(message)
                    
                    elif user_choice == "6":
                        current_user = None
                        print("Logged out successfully")
                        break
                    
                    else:
                        print("Invalid choice")
        
        elif choice == "3":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
