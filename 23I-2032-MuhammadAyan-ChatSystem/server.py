import socket
import os
import client
import Secure
from Crypto import Random
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
    if len(message) == 0:  # Check if the message is empty
        return message
    padding_length = ord(message[-1])
    if padding_length > BLOCK_SIZE:  # Check for invalid padding length
        raise ValueError("Invalid padding length")
    return message[:-padding_length]

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


def valueb(p1,g1):
    b = 5
    p = p1
    g = g1
    B = pow(g, b) % p
    return B,b

def secret_key(A1,b1,p1):
    A = A1
    b = b1
    p = p1
    K = pow(A, b) % p
    byte_length = 16
    K_bytes = K.to_bytes(byte_length, byteorder='big', signed=False)
    return K_bytes 

def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n")

    # create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # define the server address
    server_address = ('', 8080)

    # bind the socket to the specified IP and port
    server_socket.bind(server_address)
    server_socket.listen(5)

    while True:
        # accept incoming connections
        client_socket, client_address = server_socket.accept()

        # create a new process to handle the client
        pid = os.fork()
        if pid == -1:
            print("Error! Unable to fork process.")
        elif pid == 0:
            # child process handles the client
            handle_client(client_socket)
            os._exit(0)
        else:
            # parent process continues accepting clients
            client_socket.close()

def handle_client(client_socket):
    # Get the AES secret key
    
    
   req=client_socket.recv(256).decode('utf-8')
   print("client: ",req)
    
   print("recieved registeration or login request")
   msg="Starting key exchange"
   client_socket.send(msg.encode('utf-8'))
   line=client_socket.recv(256).decode('utf-8')
   print("client: ", line)
   parts = line.strip().split(",")
   A = int(parts[0].split(":")[1].strip().strip('"'))
   a = int(parts[1].split(":")[1].strip().strip('"'))
   g = int(parts[2].split(":")[1].strip().strip('"'))
   p = int(parts[3].split(":")[1].strip().strip('"'))
   B,b=valueb(p,g)
   key = secret_key(A,b,p)
   print("Secret key generated")
   client_socket.send(f'B:"{B}"'.encode('utf-8'))
   if(req=="register"):
       creds=client_socket.recv(256).decode('utf-8')
       dec_cred= decrypt_message(creds,key)
       credp=dec_cred.strip().split(",")
       email=credp[0]
       name=credp[1]
       pin=credp[2]
       check=Secure.sign_up(email,name,pin)
       checksend=f"{check}"
       client_socket.send(checksend.encode('utf-8'))
       
   creds=client_socket.recv(256).decode('utf-8')
   dec_cred= decrypt_message(creds,key)
   credp=dec_cred.strip().split(",") 
   name=credp[0]
   pin=credp[1]
   check= Secure.sign_in(name,pin)
   checksend=f"{check}"
   client_socket.send(checksend.encode('utf-8'))
    

       
       
       
   while True:
        # Receive encrypted message from the client
        encrypted_message = client_socket.recv(256).decode('utf-8')

        # If client sends "exit", close the connection
       
        # Decrypt the client's message
        message = decrypt_message(encrypted_message, key)
        if message =="exit":
            print("Client disconnected from chat.")
            break
        
        print("Client:", message)
        
        # Send a response back to the client
        response = input("You (Server): ")
        encrypted_response = encrypt_message(response, key)
        client_socket.send(encrypted_response.encode('utf-8'))

   client_socket.close()


if __name__ == "__main__":
    main()


