# Compiler and Linker
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
SSL_DIR = ssl_certs

# Source and Object Files
SOURCES = $(SRC_DIR)/server.c $(SRC_DIR)/client.c
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Targets
TARGETS = $(BIN_DIR)/server $(BIN_DIR)/client

# Default Target
all: check_dependencies generate_ssl_certs $(TARGETS)

# Check and Install Dependencies if Necessary
check_dependencies:
	@which apt-get > /dev/null && { \
		echo "Updating package lists..."; \
		sudo apt-get update; \
		echo "Installing build-essential and libssl-dev..."; \
		sudo apt-get install -y build-essential libssl-dev; \
	} || { \
		echo "apt-get not found. Please install build-essential and libssl-dev manually."; \
	}

# Generate SSL Certificates
generate_ssl_certs: | $(SSL_DIR)
	@echo "Generating SSL certificates..."
	openssl genpkey -algorithm RSA -out $(SSL_DIR)/server.key
	openssl req -new -key $(SSL_DIR)/server.key -out $(SSL_DIR)/server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
	openssl x509 -req -in $(SSL_DIR)/server.csr -signkey $(SSL_DIR)/server.key -out $(SSL_DIR)/server.crt

# Ensure that obj, bin, and ssl_certs directories exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(SSL_DIR):
	mkdir -p $(SSL_DIR)

# Build Server
$(BIN_DIR)/server: $(OBJ_DIR)/server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build Client
$(BIN_DIR)/client: $(OBJ_DIR)/client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile Source Files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean Up
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SSL_DIR)

.PHONY: all clean check_dependencies generate_ssl_certs
