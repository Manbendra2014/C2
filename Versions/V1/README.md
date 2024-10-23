# Command and Control Server - Version 1

This document outlines the features of the Command and Control Server developed in three main components : **Reverse Proxy** , **Client** and **Server**. Each component serves a specific role in enabling communication and command execution in a networked environment.

## Table of Contents
- [1. Client](#1-client)
- [2. Server](#2-server)
- [3. Reverse Proxy](#3-reverse-proxy)

---

## 1. Client

The **client** is responsible for sending commands to the server through the proxy. It establishes a connection, sends commands, and receives execution results.

### Key Features :
- **Command Execution** : Sends system commands to the server for execution.
- **Output Retrieval** : Receives and processes the output of executed commands, including error handling.
- **Username Transmission** : Sends the current username to the server for logging and identification purposes.
- **Graceful Shutdown** : Listens for an exit command to terminate the connection and shutdown gracefully.

---

## 2. Server

The **server** is responsible for executing commands received from the client and managing user directories for storing command outputs.

### Key Features:
- **Directory Management** : Creates user-specific directories based on usernames and organizes command outputs by date and time.
- **Command Reception** : Accepts commands from the client and executes them on the server.
- **Output Logging** : Logs command outputs in user-specific directories, including execution date and time.
- **Help Command** : Provides users with a list of available commands and their descriptions, enhancing user experience.

---

## 3. Reverse Proxy

The **reverse proxy** acts as an intermediary between the client and the server. It listens for incoming connections, forwards client requests to the server, and sends the server's responses back to the client.

### Key Features :
- **Socket Communication** : Establishes a TCP connection to facilitate communication between client and server.
- **Request Forwarding** : Receives requests from clients and forwards them to the specified main server.
- **Response Handling** : Sends back responses from the server to the respective clients, maintaining the connection until closure.
- **Logging** : Provides console output for received requests, forwarded requests, and disconnections.


---
