#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "pbc/pbc.h"
#include "pbc/pbc_test.h"

#define PORT 12345
#define BUFFER_SIZE 1024

void init_elements(pairing_t pairing, element_t *P,element_t *g, element_t *Ppub, element_t *Smk) {
    element_init_G1(*P, pairing);
    element_init_G2(*g, pairing);
    element_init_G1(*Ppub, pairing);
    element_init_Zr(*Smk, pairing);

    element_random(*P);
    element_random(*Smk);
    element_mul_zn(*Ppub, *P, *Smk);
}

int main(int argc, char **argv) {
    pairing_t pairing;
    pbc_demo_pairing_init(pairing, argc, argv);

    // Initialize elements
    element_t P, g, Ppub, Smk, encrypted_message, decrypted_message, message, t1, t2;
    
    init_elements(pairing, &P, &g, &Ppub, &Smk);

    // Create server socket
    int server_fd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while (1) {  // Loop to keep accepting new connections
        // Accept client connection
        client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Client connection failed");
            close(server_fd);
            continue;  // Continue accepting other connections
        }

        printf("Client connected.\n");

        // Handle multiple messages from the same client
        while (1) {
            // Receive the encrypted message from the client
            char buffer[BUFFER_SIZE];
            ssize_t bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0);
            if (bytes_received < 0) {
                perror("Failed to receive message");
                break;  // Break out of the inner loop and continue accepting new clients
            }

            if (bytes_received == 0) {
                printf("Client disconnected.\n");
                break;  // Client closed the connection
            }

            // Convert received data into element and decrypt
            element_init_G1(encrypted_message, pairing);
            element_from_bytes(encrypted_message, (unsigned char *)buffer);
            
            // Decrypt the message
            element_init_G1(decrypted_message, pairing);
            element_random(decrypted_message);
	   element_printf("receive message is %B\n", decrypted_message);
           // element_div(decrypted_message, encrypted_message, Smk);  // Decrypt: message = encrypted_message / Smk

            // Print the decrypted message
           // element_printf("Decrypted message: %B\n", decrypted_message);

            // Send the decrypted message back to the client
            element_to_bytes((unsigned char *)buffer, decrypted_message);
            if (send(client_sock, buffer, bytes_received, 0) < 0) {
                perror("Failed to send decrypted message");
            }
         printf("Authentication message sent to client, bytes_sent: %zd\n", bytes_received);
           
            ssize_t bytes_received1 = recv(client_sock, buffer, BUFFER_SIZE, 0);
            if (bytes_received1 < 0) {
                perror("Failed to receive message");
                break;  // Break out of the inner loop and continue accepting new clients
            }

            if (bytes_received1 == 0) {
                printf("Client disconnected.\n");
                break;  // Client closed the connection
            }

           element_init_Zr(message, pairing);
           element_from_bytes(message, (unsigned char *)buffer);
           element_init_G1(t1, pairing);
           element_init_G1(t2, pairing);
           element_mul_zn(t1,P,message);
           element_mul_zn(t2,Ppub,decrypted_message);

           if (element_cmp(t1, t2)){
                printf("Authentication Success. Start session...\n");
            }
            else{
                printf("Authenticatio fail. Try again, please.\n");
            }
            
            
            // Clean up the elements for the next message

            element_clear(message);
            element_clear(encrypted_message);
            element_clear(decrypted_message);
        }

        // Close the client socket after handling the client
        close(client_sock);
    }

    // Clean up and close the server socket when done (this will never be reached because of the infinite loop)
    element_clear(P);
    element_clear(g);
    element_clear(Ppub);
    element_clear(Smk);
    element_clear(t1);
    element_clear(t2);
    close(server_fd);

    return 0;
}
