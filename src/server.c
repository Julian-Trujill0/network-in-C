#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define MAX_CLIENTS 5
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

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to configure SSL context
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load certificate file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load private key file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the public certificate");
        exit(EXIT_FAILURE);
    }
}

// Function to handle client communication
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Receive message from client
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        perror("SSL read failed");
    } else {
        buffer[bytes] = '\0';
        printf("Received: %s\n", buffer);

        // Send acknowledgment
        SSL_write(ssl, "Message received!", strlen("Message received!"));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    int sockfd, clientfd;
    struct sockaddr_in addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept incoming connections
    while (1) {
        clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (clientfd < 0) {
            perror("Accept failed");
            continue;
        }

        // Create SSL object
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            perror("SSL handshake failed");
        } else {
            // Handle communication with the client
            handle_client(ssl);
        }

        close(clientfd);
    }

    // Clean up
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
