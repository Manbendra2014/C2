import socket
import threading
import select
import os
from datetime import datetime, timezone
import ssl

def log_message(log_file, message):
    timestamp = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    with open(log_file, 'a') as f:
        f.write(f"{timestamp} - {message}\n")
    print(f"{timestamp} - {message}")

def create_log_file():
    current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log_dir = os.path.join("./logs", current_date)
    os.makedirs(log_dir, exist_ok=True)
    start_time = datetime.now(timezone.utc).strftime('%H-%M-%S')
    log_file = os.path.join(log_dir, f"proxy_log_{start_time}.log")
    return log_file

def handle_connection(client_socket, server_socket, log_file, client_ip):
    sockets = [client_socket, server_socket]
    while True:
        try:
            read_sockets, _, _ = select.select(sockets, [], [])
            for sock in read_sockets:
                if sock == client_socket:
                    data = client_socket.recv(4096)
                    if not data:
                        log_message(log_file, f"Client {client_ip} disconnected.")
                        return
                    log_message(log_file, f"Received {len(data)} bytes from client {client_ip}.")
                    server_socket.sendall(data)
                elif sock == server_socket:
                    data = server_socket.recv(4096)
                    if not data:
                        log_message(log_file, "Server closed the connection.")
                        os._exit(0)
                        return
                    log_message(log_file, f"Received {len(data)} bytes from server.")
                    client_socket.sendall(data)
        except Exception as e:
            log_message(log_file, f"Error in connection handling: {str(e)}")
            break
    client_socket.close()
    server_socket.close()

def handle_client(client_socket, server_host, server_port, log_file, active_clients, client_ip, client_port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile="proxy_cert.pem", keyfile="proxy_key.pem")
        context.load_verify_locations(cafile="ca_cert.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        server_socket = context.wrap_socket(server_socket, server_hostname="Server")
        server_socket.connect((server_host, server_port))
        log_message(log_file, f"Connected to server at {server_host}:{server_port}.")
        ip_port_flag = f"IP_ADDRESS**{client_ip}**PORT_NUMBER**{client_port}"
        server_socket.send(ip_port_flag.encode())
        log_message(log_file, f"Sent {ip_port_flag} to the server.")
        active_clients[client_ip] = client_socket
        handle_connection(client_socket, server_socket, log_file, client_ip)
    except Exception as e:
        log_message(log_file, f"An unexpected error occurred: {str(e)}")
        client_socket.close()
        server_socket.close()
        active_clients.pop(client_ip, None)

def start_proxy(local_port, server_host, server_port):
    log_file = create_log_file()
    log_message(log_file, f"Proxy server listening on port {local_port}...")
    active_clients = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.bind(('', local_port))
        proxy_socket.listen(socket.SOMAXCONN)
        while True:
            client_socket, addr = proxy_socket.accept()
            client_ip, client_port = addr
            log_message(log_file, f"Accepted connection from {client_ip}:{client_port}")
            client_handler = threading.Thread(target=handle_client, args=(
                client_socket, server_host, server_port, log_file, active_clients, client_ip, client_port))
            client_handler.daemon = True
            client_handler.start()

if __name__ == "__main__":
    CLIENT_PORT = 8081
    SERVER_HOST = input("Server IP : ")
    SERVER_PORT = 8080
    # SERVER_HOST = '127.0.0.1'
    start_proxy(CLIENT_PORT, SERVER_HOST, SERVER_PORT)
