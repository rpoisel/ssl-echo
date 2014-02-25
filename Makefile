CC := gcc

# Debian based systems only
#CFLAGS := $(shell dpkg-buildflags --get CFLAGS) \
#    -W -Wall -g
#LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)
# all other systems
CFLAGS := -W -Wall -g
LDFLAGS := 
#DIR_BUILD := build
#DIR_BUILD := $(CURDIR)
#DIR_BUILD := /tmp/build
SRC_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

RM := rm
RMFLAGS := -rf
MKDIR := mkdir
TOUCH := touch

BIN_NOSSL := $(CURDIR)/echo_server
SRC_NOSSL := \
    echo_server.c \
    util_socket.c \

OBJ_NOSSL := $(addprefix $(CURDIR)/, $(SRC_NOSSL:.c=.o))

BIN_SSL := $(CURDIR)/echo_server_ssl
SRC_SSL := \
    echo_server_ssl.c \
    util_socket.c \

OBJ_SSL := $(addprefix $(CURDIR)/, $(SRC_SSL:.c=.o))


all: $(BIN_NOSSL) $(BIN_SSL)

$(CURDIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BIN_NOSSL): $(OBJ_NOSSL)
	$(CC) -o $(BIN_NOSSL) $(LDFLAGS) $(OBJ_NOSSL)

$(BIN_SSL): LDFLAGS := $(LDFLAGS) -lssl
$(BIN_SSL): $(OBJ_SSL)
	$(CC) -o $(BIN_SSL) $(LDFLAGS) $(OBJ_SSL)

.PHONY: clean

clean:
	-$(RM) $(RMFLAGS) $(BIN_NOSSL) $(BIN_SSL) $(OBJ_NOSSL) $(OBJ_SSL)
