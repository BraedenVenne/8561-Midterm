import socket
from getpass import getpass
from textwrap import dedent
from modules.http_security_checker import run_http_checker
from modules.port_scanner import run_port_scanner
from modules.send_message import send_message

HOST = "127.0.0.1"
PORT = 12345
BASE_URL = "http://127.0.0.1:8765"

client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

authenticated = False

# Username and password authentication loop
while not authenticated:
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")

    # Format and send AUTH command to server
    auth_message = f"AUTH|{username}|{password}"
    client_socket.send(
        auth_message.encode()
    )

    # Receive server response
    response = client_socket.recv(1024).decode()
    print("Server:", response)

    # If max failed attempts threshold is reached, block connection
    if "Authentication blocked" in response:
            print("Connection closed by server.")
            client_socket.close()
            exit()

    # TOTP authentication loop
    if "OTP_REQUIRED" in response:
        while True:
            client_otp = input("Enter your OTP: ")

            # Format and send OTP command  to server
            otp_message = f"OTP|{client_otp}" 
            client_socket.send(
                otp_message.encode()
            )

            # Receive server response
            response = client_socket.recv(1024).decode()
            print("Server:", response)

                # If max failed attempts threshold is reached, block connection
            if "Authentication blocked" in response:
                print("Connection closed by server.")
                client_socket.close()
                exit()

            # If TOTP is authenticated proceed to next stage
            if "ACCESS_GRANTED" in response:
                authenticated = True
                break

# User interactive menu loop
while authenticated:
    user_menu = dedent(
    f"""
    =======================================================================
    |                  Security Assessment Tools                          |
    |=====================================================================|
    |                                                                     |
    |                  [1] Run Local TCP Port Scanner                     |
    |                  [2] Run HTTP Website Security Checker              |
    |                  [3] Run Offline PCAP Analysis                      |
    |                  [4] Run Message Application                        |
    |                  [5] Exit Application                               |
    |                                                                     |
    =======================================================================
    """
    )

    print(user_menu)
    user_selection = input("Select an option (1 - 5): ")

    # Routes menu selections to corresponding modules or commands
    if user_selection == "1":
        run_port_scanner()
    elif user_selection == "2":
        run_http_checker()
    elif user_selection == "3":
        client_socket.send("PCAP|".encode())
        response = client_socket.recv(1024).decode()
        print(f"\n{response}\n")
    elif user_selection == "4":
        send_message(client_socket)
    elif user_selection == "5":
        client_socket.send("EXIT|".encode())
        response = client_socket.recv(1024).decode()
        print("Server:", response)
        break
    else:
        print("Invalid option. Select an option (1 - 5).")


# End the connection
client_socket.close()

print("Disconnected")