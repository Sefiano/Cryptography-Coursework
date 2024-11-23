# Cryptography-Coursework

## README
Encrypted File Management System
This program is a command-line application that provides a secure environment for user registration, login, and file management. The system encrypts user credentials and file content to ensure privacy and data protection.

# Features
User Management:

Registration with RSA key pair generation.
Password encryption and complexity validation.
Login with failed attempt tracking and account lockout after multiple failures.
File Management:

Create encrypted files with AES encryption.
View, append, delete, and list user-specific files.
Ensure file name and content size limitations.
Action Logging:

Track user actions (e.g., registration, login, file operations) in an admin log.
Encryption:

RSA (2048 bits) for password and file key encryption.
AES (EAX mode) for file content encryption.

Prerequisites
Python: Version 3.6 or later

Libraries:
pycryptodome (Install via pip install pycryptodome)
os, json, shutil, base64, time (Standard Python libraries)


# Usage
Main Menu
1. Register: Create a new user account.
2. Login: Access the system with your credentials.
3. Exit: Close the program.
After Login
1. List Files: Display all files owned by the logged-in user.
2. View File: Decrypt and display the content of a file.
3. Create New File: Create a new encrypted file with custom content.
4. Append to File: Add new content to an existing file.
5. Delete File: Permanently remove a file.
6. Logout: Exit the user session.
Password Policy
To enhance security, passwords must:

Be at least 8 characters long.
Contain at least one uppercase letter, one lowercase letter, one number, and one special character.
Limitations
Maximum file name length: 255 characters.
Maximum file content size: 1 MB.
Account lockout after 3 failed login attempts (reset after a successful login).
Files and Directories
user_data/: Directory for user-specific files and admin logs.
users.json: Stores encrypted user credentials and keys.
admin_log.txt: Logs user activities.
Security Notes
All passwords and file keys are encrypted using RSA.
File content is encrypted with AES for fast and secure storage.
The admin log records user actions for auditing purposes.

Author
This program is designed and maintained by Seifallah Ahmed.






