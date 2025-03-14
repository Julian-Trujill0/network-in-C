// All Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> // IP conversion functions
#include <openssl/ssl.h> // OpenSSL functions
#include <openssl/err.h> // OpenSSL error handling
#include <pthread.h> // Multi-threading support

#define PORT 8080
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define LOG_FILE "server.log"

FILE *log_file;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to log messages to a file
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "%s\n", message);
        fclose(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

// Function to start OpenSSL
void start_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void clean_openssl() {
    EVP_cleanup();
}

// Function to create an SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        log_message("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Function to configure SSL certificates
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "ssl_certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        log_message("Unable to load the certificate file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "ssl_certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        log_message("Unable to load the private key file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        log_message("Private key does not match the public certificate");
        exit(EXIT_FAILURE);
    }
}

// Function to handle client communication
void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;

    // Receive message from client
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        log_message("SSL read failed");
        ERR_print_errors_fp(stderr);
    } else {
        buffer[bytes] = '\0'; // Proper null termination
        log_message(buffer);
        printf("Received: %s\n", buffer);
        SSL_write(ssl, "Message received!", strlen("Message received!"));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx;
    pthread_t thread_id;

    // Initialize OpenSSL
    start_openssl();
    ctx = create_context();
    configure_context(ctx);

    // Create server socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);
    log_message("Server started");

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        // Create SSL object
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            log_message("SSL handshake failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        log_message("Client connected");

        // Create a new thread for each client
        if (pthread_create(&thread_id, NULL, handle_client, (void *)ssl) != 0) {
            log_message("Failed to create thread");
        }
        pthread_detach(thread_id);
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    clean_openssl();
    pthread_mutex_destroy(&log_mutex);

    return 0;
}
