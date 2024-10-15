import socket
from Crypto.Cipher import AES
import hashlib
import base64

BLOCK_SIZE = 16  # AES block size is 16 bytes

# Helper function to pad the message
def pad(message):
    padding_length = BLOCK_SIZE - len(message) % BLOCK_SIZE
    return message + chr(padding_length) * padding_length

# Helper function to unpad the message after decryption
def unpad(message):
    return message[:-ord(message[-1])]

# Encrypt message using AES
def encrypt_message(message, key):
    message = pad(message)
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:BLOCK_SIZE])  # Use the first 16 bytes of the key as IV
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

# Decrypt message using AES
def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:BLOCK_SIZE])
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    return unpad(decrypted_message)

def valuea():
    a = 2
    p = 47
    g = 13
    A = pow(g, a) % p
    return A, a, p, g

def secretkey(B1, a1, p1):
    B = B1
    a = a1
    p = p1
    K = pow(B, a) % p
    byte_length = 16
    K_bytes = K.to_bytes(byte_length, byteorder='big', signed=False)
    return K_bytes  

def create_socket():
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Setup an address
    server_address = ('localhost', 8080)
    sock.connect(server_address)
    
    return sock

def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n")

    # Create socket and connect to the server
    sock = create_socket()

    choice = input("Enter whether to register or login: ")
    
    print("Sending registration request")
    sock.send(choice.encode('utf-8'))
    res = sock.recv(256).decode('utf-8')
    print(res)

    # Generate values A, a, g, p
    A, a, p, g = valuea()
    print(f'A:"{A}",a:"{a}",g:"{g}",p:"{p}"')
    sock.send(f'A:"{A}",a:"{a}",g:"{g}",p:"{p}"'.encode('utf-8'))

    line = sock.recv(256).decode('utf-8')
    print("Received line:", line)
        
    # Extract B from the received line
    parts = line.strip().split(":")
    B = int(parts[1].strip().strip('"')) # Convert to int

    # Get the AES secret key
    key = secretkey(B, a, p)
    if choice == "register":
        print("Secret key generated")
        print("Enter registration details")
        email=input("Enter email: ")
        name=input("Enter name: ")
        pin=input("Enter password: ")
        creds=f"{email},{name},{pin}"
        enc_cred=encrypt_message(creds,key)
        sock.send(enc_cred.encode('utf-8'))
        data=sock.recv(256).decode('utf-8')
        check=int(data.strip('"'))
        if check == 0:
            print("Registration failed! Please try again")
            sock.close()
            return
        else:
            print("Account Registered successfully")
        
    print("Enter login credentials")
    name=input("Enter Username: ")
    password=input("Enter password: ")
    creds=f"{name},{password}"
    enc_cred=encrypt_message(creds,key)
    sock.send(enc_cred.encode('utf-8'))
    data=sock.recv(256).decode('utf-8')
    check=int(data.strip('"'))
    if check == 0:
        sock.close()
        return
    else:
         print("Account Registered successfully")
        
        

    while True:
        # Get user input and encrypt it
        message = input("You (Client): ")
        encrypted_message = encrypt_message(message, key)

        # Send the encrypted message to the server
        sock.send(encrypted_message.encode('utf-8'))

        # If the client sends "exit", terminate the chat
        if message == "exit":
            print("You disconnected from the chat.")
            break

        # Receive encrypted response from server
        encrypted_response = sock.recv(256).decode('utf-8')

        # Decrypt the server response
        response = decrypt_message(encrypted_response, key)
        print("Server:", response)

    # Close the socket after communication
    sock.close()

if __name__ == "__main__":
    main()
