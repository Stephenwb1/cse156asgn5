CC = gcc
CFLAGS = -Wall -Wextra -pthread -I/usr/include/openssl
LDFLAGS = -pthread -L/usr/lib/x86_64-linux-gnu -lssl -L/usr/lib/x86_64-linux-gnu -lcrypto
BIN_DIR = bin
SRC_DIR = src
DOC_DIR = doc

.PHONY: all clean

all: $(BIN_DIR)/myproxy

$(BIN_DIR)/myproxy: $(SRC_DIR)/myproxy.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/myproxy
