CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic

.PHONY: all clean

all: udp-loadgen

udp-loadgen: udp-loadgen.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f udp-loadgen
