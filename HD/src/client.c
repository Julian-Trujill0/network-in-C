// All Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // IP address conversion
#include <unistd.h>     // close()
#include <openssl/ssl.h> // OpenSSL functions
#include <openssl/err.h> // OpenSSL error handling

#define SERVER_IP "127.0.0.1" // Fixed typo
#define PORT 8080
#define BUFFER_SIZE 1024

// Function to start OpenSSL
void start_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void clean_openssl()
{
    EVP_cleanup();
}

// Function to create an SSL context
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to communicate with the server
void communicate_server(SSL *ssl)
{
    char buffer[BUFFER_SIZE];

    // Get user input
    printf("Enter message: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Send message to server
    SSL_write(ssl, buffer, strlen(buffer));

    // Read server's response
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));

    if (bytes <= 0)
    {
        perror("SSL read failed");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        buffer[bytes] = '\0';
        printf("Server response: %s\n", buffer);
    }
}

int main()
{
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize OpenSSL
    start_openssl();
    ctx = create_context();

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // sockaddr_in fields
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Create SSL object and associate it with the socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0)
    {
        perror("SSL handshake failed");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        communicate_server(ssl);
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    clean_openssl();

    return 0;
}
