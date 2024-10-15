import re
import hashlib
import os


# Regular expression for validating an email
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

def is_valid_email(email):
    """Check if the email is valid based on the regex pattern."""
    return re.match(EMAIL_REGEX, email) is not None

def generate_salt():
    """Generates a random 16-byte salt."""
    return os.urandom(12).hex()

def hash_password(password, salt):
    """Hashes the password using SHA-256 along with the salt."""
    salted_password = password + salt
    sha_signature = hashlib.sha256(salted_password.encode()).hexdigest()
    return sha_signature

def sign_up(email,username,password):

    if not is_valid_email(email):
        print("Invalid email format. Please enter a valid email.")
        return 0

    # Generate a random salt
    salt = generate_salt()

    # Hash the password with the salt
    hashed_password = hash_password(password, salt)

    try:
        with open("credentials.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                # Skip empty or improperly formatted lines
                parts = line.strip().split(",")
                if len(parts) < 2:
                    continue

                stored_username = parts[1].strip()  # assuming format is email, username, hashed_password, salt
                if stored_username == username:
                    print("Username already exists. Try again with a different username.")
                    return 0
    except FileNotFoundError:
        # If file doesn't exist, this will be the first entry
        pass

    with open("credentials.txt", "a") as file:
        # Store email, username, hashed password, and salt
        file.write(f"{email},{username},{hashed_password},{salt}\n")
        print("User registered successfully!")
        return 1


def sign_in(username, password):

    try:
        with open("credentials.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                # Ignore empty or improperly formatted lines
                parts = line.strip().split(",")
                if len(parts) != 4:
                    continue  # Skip lines that don't have exactly 4 values

                stored_email, stored_username, stored_hashed_password, stored_salt = parts

                if stored_username == username:
                    # Hash the entered password with the stored salt
                    hashed_password_attempt = hash_password(password, stored_salt)

                    # Compare the hashed passwords
                    if hashed_password_attempt == stored_hashed_password:
                        print("Login successful!")
                        return 1
                    else:
                        print("Incorrect password. Try again.")
                        return 0

            print("Username not found. Please sign up.")
            return 0
    except FileNotFoundError:
        print("No users registered yet. Please sign up.")
        
    


