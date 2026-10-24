# Main message function
def send_message(client_socket):
    # Message application loop
    while True:
        message = input(
            "Enter message or type EXIT to return to the menu: "
        )

        # Allow user to type 'EXIT' to end the connection
        if message.upper() == "EXIT":
            break
        
        # Format and send MSG command to server
        protocol_message = f"MSG|{message}"
        client_socket.send(
            protocol_message.encode()
        )

        # Receive resposne
        response = client_socket.recv(1024)

        print("Server:", response.decode())
