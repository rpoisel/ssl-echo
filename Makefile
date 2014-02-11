CC := gcc
CFLAGS := $(shell dpkg-buildflags --get CFLAGS) \
    -W -Wall -g
LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)
RM := rm

BIN := echo_server
OBJ := $(patsubst %.c,%.o,$(wildcard *.c))


all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJ)

.PHONY: clean

clean:
	-$(RM) $(BIN) $(OBJ)
