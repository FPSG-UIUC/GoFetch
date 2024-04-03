CC=clang
SOURCES=$(shell find . -name '*.c')
OBJECTS=$(SOURCES:.c=.o)

CFLAGS=-O2 -Wall -fPIC -g
LDFLAGS=-lm

all: $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJECTS)
