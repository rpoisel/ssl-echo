CC := gcc

# Debian based systems only
#CFLAGS := $(shell dpkg-buildflags --get CFLAGS) \
#    -W -Wall -g
#LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)
# all other systems
CFLAGS := -W -Wall -g
LDFLAGS := 
DIR_BUILD := build

RM := rm
RMFLAGS := -rf
MKDIR := mkdir
TOUCH := touch

BIN_NOSSL := $(DIR_BUILD)/echo_server
SRC_NOSSL := \
    echo_server.c \
    util_socket.c \

OBJ_NOSSL := $(addprefix $(DIR_BUILD)/, $(SRC_NOSSL:.c=.o))

BIN_SSL := $(DIR_BUILD)/echo_server_ssl
SRC_SSL := \
    echo_server_ssl.c \
    util_socket.c \

OBJ_SSL := $(addprefix $(DIR_BUILD)/, $(SRC_SSL:.c=.o))


all: $(BIN_NOSSL) $(BIN_SSL)

$(DIR_BUILD)/.dirstamp:
	mkdir $(DIR_BUILD)
	touch $@

$(DIR_BUILD)/%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BIN_NOSSL): $(DIR_BUILD)/.dirstamp $(OBJ_NOSSL)
	$(CC) -o $(BIN_NOSSL) $(LDFLAGS) $(OBJ_NOSSL)

$(BIN_SSL): LDFLAGS := $(LDFLAGS) -lssl
$(BIN_SSL): $(DIR_BUILD)/.dirstamp $(OBJ_SSL)
	$(CC) -o $(BIN_SSL) $(LDFLAGS) $(OBJ_SSL)

.PHONY: clean

clean:
	-$(RM) $(RMFLAGS) $(DIR_BUILD)
