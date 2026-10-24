import hashlib
import logging
import sys
import socket
import pyotp
from modules.analyze_pcap import analyze_pcap

# Configure security event logging to write to both file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("security_events.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
PCAP_FILE = "FSCT8561_Operation_Sentinel_Traffic.pcap"


# Function for generating SHA-256 hash
def hash_password(password):
  return hashlib.sha256(password.encode()).hexdigest()


# Function for verifying if entered password hash matches stored password hash
def verify_password(password, stored_hash):
  if password == stored_hash:
    return True
  else:
    return False


# Function for verifying TOTP code
def verify_otp(secret, otp):
  totp = pyotp.TOTP(secret)
  return totp.verify(otp)


# Mock user database
users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": pyotp.random_base32(),
    }
}

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

# Variable declarations for connection state, user data, and failure counter
authenticated = False
username = None
password = None
connected = True
failed_attempts = 0
MAX_FAILED_ATTEMPTS = 3

# Main server connection loop
while connected:
  try:
    data = client_socket.recv(1024)

    if not data:
      print("Client disconnected unexpectedly")
      break

    message = data.decode()

    # Safely print received messages, redacting passwords if it's an AUTH command
    if message.startswith("AUTH|"):
      try:
        parts = message.split("|")
        if len(parts) >= 3:
          print(f"Received: AUTH|{parts[1]}|[REDACTED]")
        else:
          print("Received: AUTH|[REDACTED]")
      except Exception:
        print("Received: AUTH|[REDACTED]")
    else:
      print("Received:", message)

    # Enforce command structure - COMMAND|CONTENT
    if "|" not in message:
      client_socket.send("ERROR|Invalid command format".encode())
      continue

    command, content = message.split("|", 1)

    # Handle the AUTH command
    if command == "AUTH":
      username, password = content.split("|", 1)

      # Check if username is empty
      if username == "":
        client_socket.send("ERROR|Username required".encode())
      # Check if password is encrypted/empty
      elif password == "":
        client_socket.send("ERROR|Password required".encode())
      # If not empty proceed to collecting the username and password
      else:
        # Hash the inputted password and run the verification function
        current_hash = hash_password(password)
        password_verification = verify_password(
            current_hash, users["alice"]["password_hash"]
        )

        # Handles the password verification steps
        if password_verification == True:
          logging.info(f"Password verified successfully for username: {username}")
          client_socket.send("OTP_REQUIRED".encode())
          totp = pyotp.TOTP(users["alice"]["totp_secret"])

          uri = totp.provisioning_uri(
              name="alice", issuer_name="FSCT8561-Lab3"
          )
          print(uri)

        # Track failed attempts and block the connection after threshold is reached
        else:
          failed_attempts += 1
          logging.warning(
              f"Failed password attempt for username: {username} (Attempt"
              f" {failed_attempts}/{MAX_FAILED_ATTEMPTS})"
          )
          if failed_attempts >= MAX_FAILED_ATTEMPTS:
            logging.error(
                f"Client {client_address} locked out after exceeding max failed"
                " attempts."
            )
            client_socket.send(
                "ACCESS_DENIED|Too many failed attempts. Authentication"
                " blocked.".encode()
            )
            connected = False
          else:
            client_socket.send("ACCESS_DENIED".encode())

    # Handle the OTP command
    elif command == "OTP":
      # Check if OTP is empty
      if content == "":
        client_socket.send("ERROR|OTP is required.".encode())
      # If OTP is not empty proceed to verification steps
      else:
        otp_verification = verify_otp(users["alice"]["totp_secret"], content)
        if otp_verification == True:
          authenticated = True
          logging.info(
              f"User {username} successfully authenticated with MFA and granted"
              " access."
          )
          client_socket.send("ACCESS_GRANTED".encode())
        # Track failed attempts and block the connection after threshold is reached
        else:
          failed_attempts += 1
          logging.warning(
              f"Failed OTP attempt for user: {username} (Attempt"
              f" {failed_attempts}/{MAX_FAILED_ATTEMPTS})"
          )
          if failed_attempts >= MAX_FAILED_ATTEMPTS:
            logging.error(
                f"Client {client_address} locked out after exceeding max failed"
                " attempts."
            )
            client_socket.send(
                "ACCESS_DENIED|Too many failed attempts. Authentication"
                " blocked.".encode()
            )
            connected = False
          else:
            client_socket.send("ACCESS_DENIED".encode())

    # Handle the MSG command
    elif command == "MSG":
      if not authenticated:
        client_socket.send("ERROR|HELLO required first".encode())
      # Ensure message is not empty
      elif content == "":
        client_socket.send("ERROR|Message cannot be empty".encode())

      # Ensure message is not over 200 characters
      elif len(content) > 200:
        client_socket.send("ERROR|Message too long".encode())

      # Receive the user message
      else:
        print(username + " says:", content)

        client_socket.send(("OK|Message received from " + username).encode())

    # Handle the PCAP command
    elif command == "PCAP":
      if not authenticated:
        logging.warning(
            f"Unauthorized PCAP command attempt from unauthenticated client"
            f" {client_address}"
        )
        client_socket.send("ERROR|User authentication is required.".encode())
      else:
        print(f"Running PCAP analysis for authenticated user: {username}")
        results = analyze_pcap(PCAP_FILE)
        client_socket.send(f"OK|Message from Server:\n{results}".encode())

    # End the connection if the EXIT command is received
    elif command == "EXIT":
      client_socket.send("OK|Goodbye".encode())

      connected = False

    # Handle unknown commands
    else:
      client_socket.send("ERROR|Unknown command".encode())

  except ConnectionResetError:
    print("Connection reset by client")
    break

# Close connections
client_socket.close()
server_socket.close()

print("Server closed")