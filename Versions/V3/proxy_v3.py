import socket
import ssl
import threading
import select
import os
from datetime import datetime, timezone

def log_message(log_file, message):
    with open(log_file, 'a') as f:
        f.write(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} - {message}\n")
    print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} - {message}")

def create_log_file():
    current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log_dir = os.path.join("./logs", current_date)
    os.makedirs(log_dir, exist_ok=True)
    start_time = datetime.now(timezone.utc).strftime('%H-%M-%S')
    log_file = os.path.join(log_dir, f"proxy_log_{start_time}.log")
    return log_file

def handle_client(client_socket, server_host, server_port, log_file):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile="proxy_cert.pem", keyfile="proxy_key.pem")
        context.load_verify_locations(cafile="ca_cert.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        server_socket = context.wrap_socket(server_socket, server_hostname="Server")        
        server_socket.connect((server_host, server_port))
        log_message(log_file, f"Connected to server at {server_host}:{server_port}")
        client_closed = False
        server_closed = False        
        while True:
            read_sockets = [client_socket, server_socket]
            readable, _, _ = select.select(read_sockets, [], [])
            for sock in readable:
                if sock is client_socket:
                    try:
                        request = client_socket.recv(4096)
                        if not request:
                            log_message(log_file, "Client disconnected.")
                            client_closed = True
                        else:
                            log_message(log_file, f"Received {len(request)} bytes from client.")
                            server_socket.send(request)
                            log_message(log_file, "Forwarded request to server.")
                    except ConnectionResetError:
                        log_message(log_file, "Client connection reset unexpectedly.")
                        client_closed = True
                elif sock is server_socket:
                    try:
                        response = server_socket.recv(4096)
                        if not response:
                            log_message(log_file, "Server disconnected.")
                            server_closed = True
                        else:
                            log_message(log_file, f"Received {len(response)} bytes from server.")
                            client_socket.send(response)
                            log_message(log_file, "Sent response back to client.")
                    except ConnectionResetError:
                        log_message(log_file, "Server connection reset unexpectedly.")
                        server_closed = True
            if client_closed and server_closed:
                log_message(log_file, "Both client and server have disconnected. Closing connections.")
                break
    except ConnectionResetError as e:
        log_message(log_file, f"Connection error: {str(e)}. Closing connections.")
    except Exception as e:
        log_message(log_file, f"An unexpected error occurred: {str(e)}")
    finally:
        client_socket.close()
        log_message(log_file, "Closed client connection.")
        server_socket.close()
        log_message(log_file, "Closed server connection.")
        os._exit(0)

def start_proxy(local_port, server_host, server_port):
    log_file = create_log_file()
    log_message(log_file, f"Proxy server listening on port {local_port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.bind(('', local_port))
        proxy_socket.listen(5)
        while True:
            client_socket, addr = proxy_socket.accept()
            log_message(log_file, f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, server_host, server_port, log_file))
            client_handler.daemon = True
            client_handler.start()

if __name__ == "__main__":
    CLIENT_PORT = 8081
    SERVER_HOST = input("Server IP : ")
    SERVER_PORT = 8080
    start_proxy(CLIENT_PORT, SERVER_HOST, SERVER_PORT)