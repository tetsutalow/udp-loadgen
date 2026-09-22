CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic

.PHONY: all clean

all: udp-loadgen

udp-loadgen: udp-loadgen.c stun_ice.c stun_ice.h
	$(CC) $(CFLAGS) -o $@ udp-loadgen.c stun_ice.c

clean:
	rm -f udp-loadgen
