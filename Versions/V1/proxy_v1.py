import socket
import threading
import select
import os

def handle_client(client_socket, server_host, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((server_host, server_port))
        print(f"Connected to server at {server_host}:{server_port}")
        client_closed = False
        server_closed = False
        while True:
            read_sockets = [client_socket, server_socket]
            readable, _, _ = select.select(read_sockets, [], [])
            for sock in readable:
                if sock is client_socket:
                    request = client_socket.recv(4096)
                    if not request:
                        print("Client disconnected.")
                        client_closed = True
                    else:
                        print(f"Received {len(request)} bytes from client.")
                        server_socket.send(request)
                        print("Forwarded request to server.")
                elif sock is server_socket:
                    response = server_socket.recv(4096)
                    if not response:
                        server_closed = True
                    else:
                        print(f"Received {len(response)} bytes from server.")
                        client_socket.send(response)
                        print("Sent response back to client.")
            if client_closed and server_closed:
                print("Both client and server have disconnected. Closing connections.")
                break
    client_socket.close()
    server_socket.close()
    print("Closed client connection.")
    print("Closed slient connection.")
    os._exit(0)

def start_proxy(local_port, server_host, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.bind(('', local_port))
        proxy_socket.listen(5)
        print(f"Proxy server listening on port {local_port}...")
        while True:
            client_socket, addr = proxy_socket.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, server_host, server_port))
            client_handler.daemon = True
            client_handler.start()

if __name__ == "__main__":
    CLIENT_PORT = 80
    SERVER_HOST = input("Server IP : ")
    SERVER_PORT = 80
    start_proxy(CLIENT_PORT, SERVER_HOST, SERVER_PORT)