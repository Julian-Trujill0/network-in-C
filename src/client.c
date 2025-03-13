#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024


// Function to initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Function to create SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to handle communication with the server
void communicate_with_server(SSL *ssl) {
    char buffer[BUFFER_SIZE];

    // Get user input
    printf("Enter message: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Send message to the server
    SSL_write(ssl, buffer, strlen(buffer));

    // Read the server's response
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        perror("SSL read failed");
    } else {
        buffer[bytes] = '\0';
        printf("Server response: %s\n", buffer);
    }
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize OpenSSL
    init_openssl();
    ctx = create_context();

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL handshake failed");
    } else {
        // Communicate with the server
        communicate_with_server(ssl);
    }

    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
