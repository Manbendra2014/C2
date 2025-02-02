import socket
import threading
import select
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import json
import logging
import ssl

server_host = None
stored_data = None
stored_data_lock = threading.Lock()

# thread_local = threading.local()

# def get_thread_socket():
#     """Get or create the raw_socket for the current thread."""
#     if not hasattr(thread_local, "raw_socket"):
#         try:
#             print("****DOESNT EXIST****")
#             thread_local.raw_socket = socket.create_connection((server_host, 8080))
#         except Exception as e:
#             raise RuntimeError(f"Failed to create raw_socket: {str(e)}")
#     return thread_local.raw_socket

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
                    data = client_socket.recv(1024)
                    if not data:
                        log_message(log_file, f"Client {client_ip} disconnected.")
                        return
                    log_message(log_file, f"Received {len(data)} bytes from client {client_ip}.")
                    server_socket.sendall(data)
                elif sock == server_socket:
                    data = server_socket.recv(1024)
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

app = Flask(__name__)

active_clients = {}

app.logger.disabled = False

@app.route("/dataforge", methods=["POST"])
def proxy_endpoint1():
    global server_host, stored_data, raw_socket
    data_content = request.data.decode() 
    log_file = create_log_file()
    try:
        client_ip = request.remote_addr
        client_port = request.environ.get('REMOTE_PORT')
        ip_port_flag = f"IP_ADDRESS**{client_ip}**PORT_NUMBER**{client_port}"
        if client_ip not in [_[0] for _ in active_clients]:
            log_message(log_file, f"New client detected: {client_ip}:{client_port}. Adding to active clients list.")
            active_clients[(client_ip, client_port)] = True
            send_ip_port_flag = True
        else:
            log_message(log_file, f"Client {client_ip}:{client_port} is already active.")
            send_ip_port_flag = False
        with raw_socket as server_socket:
            log_message(log_file, f"Connected to server at {server_host}:8080.")
            if send_ip_port_flag:
                server_socket.send(ip_port_flag.encode())
                log_message(log_file, f"Sent {ip_port_flag} to the server.")
            log_message(log_file, f"Forwarding data to server: {data_content}")
            server_socket.sendall(data_content.encode())
            server_response = server_socket.recv(4096)
            log_message(log_file, f"Received response from server: {server_response.decode()}")                
            with stored_data_lock:
                stored_data = server_response.decode()
                log_message(log_file, "Data stored successfully.")
            return jsonify({"status": "Data forwarded successfully"}), 200
    except ssl.SSLError as ssl_error:
        error_message = f"[ERROR] SSL/TLS error: {str(ssl_error)}"
        log_message(log_file, error_message)
        return jsonify({"error": error_message}), 500
    except ConnectionResetError:
        error_message = "[ERROR] Server closed the connection unexpectedly: Connection reset by peer."
        log_message(log_file, error_message)
        return jsonify({"error": error_message}), 500
    except Exception as e:
        error_message = f"[ERROR] Unexpected error: {str(e)}"
        log_message(log_file, error_message)
        return jsonify({"error": error_message}), 500

@app.route("/querynest", methods=["POST", "GET"])
def proxy_endpoint2():
    global stored_data
    log_file = create_log_file()
    if request.method == "POST":
        try:
            data_content = request.data.decode()            
            with stored_data_lock:
                stored_data = data_content
            log_message(log_file, f"Received and stored data: {data_content}")
            print(f"Data received and stored: {data_content}")
            return jsonify({"status": "Data received and stored successfully"}), 200
        except Exception as e:
            error_message = f"[ERROR] Unexpected error: {str(e)}"
            log_message(log_file, error_message)
            print(error_message)
            return jsonify({"error": error_message}), 500
    elif request.method == "GET":
        with stored_data_lock:
            if stored_data:
                log_message(log_file, f"Fetching stored data: {stored_data}")
                print(f"Fetching stored data: {stored_data}")
                z = stored_data
                stored_data = None
                return jsonify({"stored_data": z}), 200
            else:
                log_message(log_file, "No data stored to fetch.")
                print("No data stored to fetch.")
                return jsonify({"message": "No data stored"}), 404

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

def run_app():
    app.run(host="0.0.0.0", port=8081, ssl_context=("./domain_certificates/ciphervortex_full_chain.pem", "./domain_certificates/ciphervortex.key"))
    # app.run(host="0.0.0.0", port=8081, ssl_context=("./domain_certificates/cybernova_full_chain.pem", "./domain_certificates/cybernova.key"))
    # app.run(host="0.0.0.0", port=8081)

def proxy_start():
    global server_host,raw_socket
    server_host = input("Server IP : ")
    server_port = 8080
    client_port = 8082
    raw_socket = socket.create_connection((server_host, server_port))
    proxy_thread = threading.Thread(target=start_proxy, args=(client_port, server_host, server_port))
    app_thread = threading.Thread(target=run_app)
    proxy_thread.daemon = True
    app_thread.daemon = True
    proxy_thread.start()
    app_thread.start()
    proxy_thread.join()
    app_thread.join()

if __name__ == "__main__":
    proxy_start()