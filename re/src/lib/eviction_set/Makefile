CC=clang

SOURCES=$(shell find . -name '*.c')
OBJECTS=$(SOURCES:.c=.o)

CFLAGS=-O2 -g -Wall -fPIC


all: $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJECTS)
