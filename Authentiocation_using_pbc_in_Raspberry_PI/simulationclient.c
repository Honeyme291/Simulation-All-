#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include "pbc/pbc.h"
#include "pbc/pbc_test.h"

#define SERVER_IP "10.168.134.21"  // 服务器地址(可以替换为自己服务充当服务器的地址)
#define PORT 12345
#define BUFFER_SIZE 1024
#define VECTOR_SIZE 10  // 向量的大小

// 初始化向量A和B，随机生成其元素
void init_vector(element_t *vector, pairing_t pairing) {
    for (int i = 0; i < VECTOR_SIZE; i++) {
        element_init_Zr(vector[i], pairing);
        element_random(vector[i]);  // 随机初始化每个元素
    }
}

// 计算向量A和B的点积
void dot_product(element_t *A, element_t *B, pairing_t pairing, element_t *result) {
    element_init_Zr(*result, pairing);
    element_set0(*result);  // 初始化为0

    // 计算A·B = A[0]*B[0] + A[1]*B[1] + ... + A[n-1]*B[n-1]
    for (int i = 0; i < VECTOR_SIZE; i++) {
        element_t temp;
        element_init_Zr(temp, pairing);
        element_mul(temp, A[i], B[i]);  // A[i] * B[i]
        element_add(*result, *result, temp);  // 将结果累加到result上
        element_clear(temp);  // 清理临时变量
    }

    // 打印结果
    element_printf("Dot product result: %B\n", *result);
}

void init_elements(pairing_t pairing, element_t *P, element_t *g, element_t *Ppub, element_t *Smk) {
    element_init_G1(*P, pairing);
    element_init_G1(*g, pairing);
    element_init_G1(*Ppub, pairing);
    element_init_Zr(*Smk, pairing);

    element_random(*P);
    element_random(*Smk);
    element_mul_zn(*Ppub, *P, *Smk);
}

int main(int argc, char **argv) {
    pairing_t pairing;
    pbc_demo_pairing_init(pairing, argc, argv);
    double t0, t1;

    // Initialize elements
    element_t P, g, Ppub, Smk, pk1, pk2, pk, message, r1, r2, v1, v2, temp1, temp2, U, encrypted_message, decrypted_message;
    init_elements(pairing, &P, &g, &Ppub, &Smk);
    element_t A[VECTOR_SIZE], B[VECTOR_SIZE], C[VECTOR_SIZE];

    // Create client socket
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to the server at %s:%d\n", SERVER_IP, PORT);

    // Initialize vectors A, B, C
    init_vector(A, pairing);
    init_vector(B, pairing);
    init_vector(C, pairing);

    // Calculate and output the dot product
    element_t x1, x2;
    element_init_Zr(x1, pairing);
    element_init_Zr(x2, pairing);
    dot_product(A, B, pairing, &x1);
    dot_product(A, C, pairing, &x2);
    element_printf("x1 = %B\n", x1);
    element_printf("x2 = %B\n", x2);
    element_init_G1(pk1, pairing);
  
    element_init_G1(pk2, pairing);
    element_init_G1(pk, pairing);
    element_mul_zn(pk1, P, x1);
    element_printf("Pk1 = %B\n", pk1);
    element_mul_zn(pk2, P, x2);
    element_printf("Pk2 = %B\n", pk2);
    element_add(pk, pk1, pk2);
    element_printf("Pk = %B\n", pk);

    while (1) {
	t0 = pbc_get_time();
        // Generate a message to send (for example, a random message)
        element_init_G1(message, pairing);
        element_init_G1(U, pairing);
        element_init_Zr(r1, pairing);
        element_random(r1);
        element_printf("r1 = %B\n", r1);
        element_init_Zr(r2, pairing);
        element_random(r2);
        element_printf("r2= %B\n", r2);
 	element_init_G1(temp1, pairing);
	 element_init_G1(temp2, pairing);
        element_mul_zn(temp1, P, r1);
        element_mul_zn(temp2, P, r2);
        element_add(U, temp1, temp2);
	 element_printf("U = %B\n", U);
        // Send the message to the server
        char buffer[BUFFER_SIZE];
        element_to_bytes((unsigned char *)buffer, U);
        ssize_t bytes_sent = send(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_sent < 0) {
            perror("Failed to send message");
            break;
        }
        printf("Authentication message sent to server, bytes_sent: %zd\n", bytes_sent);


        // Receive the response from the server
        ssize_t bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("Failed to receive message");
            break;
        } else if (bytes_received == 0) {
            printf("Server closed the connection\n");
            break;
        }
  	printf("Cleint is received message from server, bytes_sent: %zd\n", bytes_received);
        element_init_G1(decrypted_message, pairing);
        element_from_bytes(decrypted_message, (unsigned char *)buffer);
	element_init_G1(temp1, pairing);
        element_init_G1(temp2, pairing);
	element_init_G1(v1, pairing);
	element_init_G1(message, pairing);
        element_init_G1(v2, pairing);
        // Print the decrypted message
        element_mul_zn(temp2,decrypted_message,x1);
        element_add(temp1,r1,x1);
        element_add(v1,temp1,temp2);

        element_mul_zn(temp2,decrypted_message,x2);
        element_add(temp1,r2,x2);
        element_add(v2,temp1,temp2);
        element_add(message,v1,v2);
        element_to_bytes((unsigned char *)buffer, message);
        ssize_t bytes_sent1 = send(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_sent1 < 0) {
            perror("Failed to send message");
            break;
        }
        printf("Authentication message sent to server, bytes_sent: %zd\n", bytes_sent1);

	t1 = pbc_get_time();
        printf("Authentication All time = %fs\n", t1 - t0);
        // Clean up the elements for the next message
        element_clear(message);
        element_clear(U);
        element_clear(decrypted_message);
        // Wait before sending the next message
        sleep(1);  // 1 second delay between sending messages

        // Process the server response (for example, verify a signature or perform other operations)
    }

    // Cleanup
    close(sock);
    return 0;
}

