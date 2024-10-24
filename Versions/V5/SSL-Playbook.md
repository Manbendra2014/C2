# Certificate and Key Generation with OpenSSL

This document provides step-by-step instructions on how to generate CA, server, and proxy certificates using OpenSSL.

## Prerequisites

Ensure you have OpenSSL installed on your machine. You can verify this by running :

### On Linux (Ubuntu/Debian) : 

#### Step 1 : Open a Terminal

First, launch a terminal window.

### Step 2 : Run the Following Command

To verify if OpenSSL is installed on your system, type the following command and press **Enter**.

```bash
openssl version
```

If OpenSSL is installed, this command will return the version number

If OpenSSL is not installed, you'll see a message like ```command not found```.

### On Windows : 

### Step 1 : Open Command Prompt or PowerShell

First, launch the command prompt or the powerShell.

### Step 2 : Run the Following Command

To verify if OpenSSL is installed on your system, type the following command and press **Enter**.

```bash
openssl version
```

If OpenSSL is installed, it will display the version number.

If OpenSSL is not installed, you may see an error like ```'openssl' is not recognized as an internal or external command```.

---

If not installed, you can install OpenSSL via package managers :

### On Linux (Ubuntu/Debian) : 

```bash
sudo apt-get install openssl
```

### On Windows : 

Download it from the official [OpenSSL](https://www.openssl.org/) website.

## Steps to Execute

### Generate the CA Private Key 

The CA (Certificate Authority) private key is used to sign other certificates. To generate it, run the following command.

```bash
openssl genrsa -out ca_key.pem 2048
```

This creates a 2048-bit private key and stores it in ca_key.pem.

### Generate the CA Certificate 

Using the CA private key, generate a self-signed CA certificate.

```bash
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 -out ca_cert.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=My CA"
```

This command creates a certificate (ca_cert.pem) valid for 365 days with the provided subject details.

### Generate the Server Private Key 

To generate the private key for the server.

```bash
openssl genrsa -out server_key.pem 2048
```

The server's private key is saved as server_key.pem.

### Generate the server CSR (Certificate Signing Request) 

Next, create a Certificate Signing Request (CSR) for the server.

```bash
openssl req -new -key server_key.pem -out server_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Server"
```

This command generates a CSR (server_csr.pem) with the provided subject details.

### Create the Server Certificate signed by the New CA 

Now, sign the server's CSR using the CA's certificate and key to create the server certificate.

```bash
openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -days 365 -sha256
```

This produces the server certificate server_cert.pem valid for 365 days, signed by the CA. The CAcreateserial flag creates a serial number file (ca_cert.srl).

### Generate the Proxy Private Key 

Generate the private key for the proxy.

```bash
openssl genrsa -out proxy_key.pem 2048
```

The proxy's private key is saved as proxy_key.pem.

### Generate the proxy CSR (Certificate Signing Request)

Next, create a CSR for the proxy.

```bash
openssl req -new -key proxy_key.pem -out proxy_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Proxy"
```

This generates a CSR (proxy_csr.pem) for the proxy.

### Create the proxy certificate signed by the same CA

Finally, sign the proxy's CSR using the CA's certificate and key to create the proxy certificate.

```bash
openssl x509 -req -in proxy_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out proxy_cert.pem -days 365 -sha256
```

This generates the proxy certificate proxy_cert.pem, also valid for 365 days and signed by the CA.

## Summary of Generated Files

### CA :

- `ca_key.pem`: CA private key
- `ca_cert.pem`: CA certificate
- `ca_cert.srl`: Serial file generated while signing

### Server :

- `server_key.pem` : Server private key
- `server_csr.pem` : Server Certificate Signing Request (CSR)
- `server_cert.pem` : Server certificate signed by CA

### Proxy :

- `proxy_key.pem` : Proxy private key
- `proxy_csr.pem` : Proxy Certificate Signing Request (CSR)
- `proxy_cert.pem` : Proxy certificate signed by CA

## Summary

This file provides a clear set of instructions on how to execute the OpenSSL commands and explains the resulting files generated at each step.
