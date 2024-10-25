
# sample user database (in a real-world scenario, this would be a secured database)
user_database = {
    "admin": "password123"  # In a real application, never store plain-text passwords
}

# Function to hash a password 
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Hash the password and update the database - simulating secure storage
user_database["admin"] = hash_password(user_database["admin"])

# Login function with basic input sanitization
def login(username, password):
    # Sanitize inputs to avoid code injection attacks
    sanitized_username = username.replace(";", "").replace("--", "")
    
    # Check if user exists
    if sanitized_username in user_database:
        # Verify the password by comparing the hashed version
        if user_database[sanitized_username] == hash_password(password):
            print("Login successful!")
        else:
            print("Invalid password. Please try again.")
    else:
        print("Username not found.")

# Basic user interaction with system
def main():
    print("Welcome to the Secure System")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    login(username, password)

if __name__ == "__main__":
    main()
    
