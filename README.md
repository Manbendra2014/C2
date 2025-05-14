# Command and Control (C2) Server

## What is a Command and Control Server ?

<p align="justify">
A <b>Command and Control (C2)</b> server is a tool used to remotely manage systems and devices. It can send commands, receive data, and execute tasks on client machines, typically in a networked environment. While C2 systems are often used in cybersecurity research, they can also be used maliciously by attackers to control compromised systems.
</p>

<p align="justify">
This tool is made as part of a B.Tech Project, and is meant to closely resemble an enterprise-level C2 / red-teaming framework.  That said, it does provide actual data exfiltration and RCE, and hence <b>must be executed only on systems where permission has been granted by the owner</b>.
</p>

All versions of the tool can be found in the repo, with the latest being **V15**.

## Setup Instructions

### Requirements and Startup

<p align="justify">
The client side executable is made with the intention that it must be able to run on ANY windows system, and hence only depends on dynamically linked DLLs present in the Windows SDK.  For the sake of creating an executable, we have dynamically linked all libraries, but uncommon libraries can be statically linked to avoid runtime issues on victim machines.
</p>

To create the executable, run 
`gcc -w -o client15.exe client_v15.c anti-debug.c sandbox.c -Wl,-Bstatic -lcrypto -lssl -lz -Wl,-Bdynamic -lws2_32 -lgdi32 -lbcrypt -lcrypt32 -lcurl -ljansson -lnetapi32 -liphlpapi` 

As for server and proxy, run `pip3 install -r requirements.txt` to install all 3rd party requirements.

### Setup 

#### Server

1. Download all the requirements by running the pip command.
2. Place the server in the attacker system, along with the three certificates required (server_cert, server_key, ca_cert).
3. Run the server.

#### Proxy

1. Repeat the steps done in the server, except this time use the certificates pertaining to the proxy-server connection (proxy_cert, proxy_key, ca_cert), and run the proxy.
2. As the proxy requests for an IP, add the server's public IP address.

#### Client

1. Compile the file with the command given above.
2. Execute the client to begin reconnissance.

## Updates in Version 15

The current version V15.  Some of the key features in this version includ e:

1. Menu-Driven Attack UI : Utilize the several options provided through the CLI based UI
2. Isolated Attack Server : All commands will be relayed through a WebServer capable of providing HTTPS connections, negating MITMs
3. Robust Encryption Standards : All data transmitted in the C2 channel is encrypted under AES-128 with a newly determined shared key for each client connection
4. Evasive Module : Client executable has inbuilt precautions to detect detection, and evade accordingly
5. Bandwidth Limited File Transfer : Using compression algorithms, file transfer is performed to avoid unnatural system resource spikes

## Future Versions

As development continues, new features and improvements will be added in future versions.

All previous versions along with source codes and all required files are available in the repository.

## Disclaimer

This software is for educational and research purposes only. Ensure you have proper authorization before using it on any network or system. The creators are not responsible for any misuse or consequences that arise from its use.
