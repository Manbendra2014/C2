# Command and Control Server - Version 2

## Table of Contents
1. [Client Modifications](#client-code-changes)
2. [Server Modifications](#server-code-changes)
3. [Reverse Proxy Modifications](#proxy-code-changes)

## Client Modifications

The following modifications to the **client** reflect enhancements made from its previous version , **Version 1**.
| Change Type | Description |
|-------------|-------------|
| **Updated** | The socket connection setup has been encapsulated in a function `create_socket()`. |
| **Updated** | The server connection is now done in a separate function `connect_to_server()`. |
| **Added**   | The client now sends the username using `getpass.getuser()`. |
| **Updated** | Handling for script execution has been improved with the addition of a temporary file for PowerShell scripts. |
| **Updated** | Improved error handling during script execution and file management (temp file deletion). |
| **Updated** | The way commands and responses are processed has been refined, ensuring better output management. |

## Server Modifications

The following modifications to the **server** reflect enhancements made from its previous version , **Version 1**.

| Change Type | Description |
|-------------|-------------|
| **Updated** | The way logs are managed has been improved with the addition of logging functionality using a log file. |
| **Added**   | Directory structure for logging is created, including date-based folders. |
| **Updated** | The handling of recon commands is now more structured with logs for each command execution. |
| **Updated** | The structure of output handling has been enhanced for clarity and organization. |
| **Added**   | Logging of connection attempts, including domain and username parsing, has been added. |

## Reverse Proxy Modifications

The following modifications to the **reverse proxy** reflect enhancements made from its previous version , **Version 1**.

| Change Type | Description |
|-------------|-------------|
| **Added**   | Proxy server logging functionality has been introduced, including connection details. |
| **Updated** | The proxy server now uses threading to handle multiple client connections concurrently. |
| **Updated** | Added checks to ensure proper closing of client and server connections, including logging of disconnections. |
| **Updated** | Improved error handling for connection resets and unexpected exceptions. |
| **Updated** | Log messages now include timestamps and are saved in a structured format based on the current date. |
