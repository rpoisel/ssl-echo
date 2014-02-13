CC := gcc
CFLAGS := $(shell dpkg-buildflags --get CFLAGS) \
    -W -Wall -g
LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)
RM := rm

BIN_NOSSL := echo_server
OBJ_NOSSL := $(patsubst %.c,%.o, \
    echo_server.c \
    )
BIN_SSL := echo_server_ssl
OBJ_SSL := $(patsubst %.c,%.o, \
    echo_server_ssl.c \
    )


all: $(BIN_NOSSL) $(BIN_SSL)

$(BIN_NOSSL): $(OBJ_NOSSL)
	$(CC) $(LDFLAGS) -o $(BIN_NOSSL) $(OBJ_NOSSL)

$(BIN_SSL): LDFLAGS := $(LDFLAGS) -lssl
$(BIN_SSL): $(OBJ_SSL)
	$(CC) $(LDFLAGS) -o $(BIN_SSL) $(OBJ_SSL)

.PHONY: clean

clean:
	-$(RM) $(BIN_NOSSL) $(OBJ_NOSSL) $(BIN_SSL) $(OBJ_SSL)
