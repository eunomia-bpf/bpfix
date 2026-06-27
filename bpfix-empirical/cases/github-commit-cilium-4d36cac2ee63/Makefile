SHELL := /bin/bash
CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -I /usr/include -D__TARGET_ARCH_x86 -mcpu=v3
PIN ?= /sys/fs/bpf/$(notdir $(CURDIR))
LOG_LIMIT ?= 8000000

.PHONY: all verify replay-verify clean

all: prog.o

prog.o: prog.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
	$(BPFTool) -d prog load prog.o $(PIN)

replay-verify: prog.o
	rm -f replay-verifier.log
	set -o pipefail; $(BPFTool) -d prog load prog.o $(PIN) 2>&1 | tail -c $(LOG_LIMIT) > replay-verifier.log

clean:
	rm -f prog.o replay-verifier.log
