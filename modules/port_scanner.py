import socket
import nmap

# function to prompt and validate port numbers between 1 and 65536
def get_valid_port(prompt):
    while True:
        try:
            port = int(input(prompt))
            if 1 <= port <= 65535:
                return port
            print("Invalid value: port out of range (1 - 65535)")
        except ValueError:
            print("Invalid - input a valid number")

# Main port scanner execution function
def run_port_scanner():
    scanner = nmap.PortScanner()
    
    # Target host input validation loop
    while True:
        target = input("Enter target host: ")
        try:
            target_ip = socket.gethostbyname(target)
            break
        except socket.gaierror:
            print("Invalid hostname or IP address")

    # Get start port
    start_port = get_valid_port("Enter start port: ")

    # Get end port
    while True:
        end_port = get_valid_port("Enter end port: ")
        if end_port > start_port:
            break
        print("Invalid entry, end port cannot be less than or equal to start port")

    # Run Nmap scan on target host and port range
    print(f"Scanning {target_ip}...\n")
    scanner.scan(
        target_ip, 
        f"{start_port}-{end_port}"
        )

    # Table header
    print("PORT\t\tSTATE\t\tSERVICE")

    # Access the port data in the dictionary and print results
    if target_ip in scanner.all_hosts() and scanner[target_ip]["tcp"]:
        for port, data in scanner[target_ip]["tcp"].items():
            # Label service as unknown if data is empty
            if data["name"] == '':
                print(f"{port}\t\t{data["state"]}\t\tunknown")
            else:
                print(f"{port}\t\t{data["state"]}\t\t{data["name"]}")

    print("\nScan complete. Returning to menu...")
