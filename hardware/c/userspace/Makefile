# Nevelio Hardware Security — Userspace C Tools Build
#
# Outils : rowhammer_test (test standalone sans Rust)
#
# Usage :
#   make              # compiler rowhammer_test
#   make test-safe    # lancer un test rapide (5s, 100K iter, 64MB) — sans danger
#   make clean

CC      := gcc
CFLAGS  := -O2 -march=native -Wall -Wextra -DROWHAMMER_STANDALONE
LDFLAGS :=

UNAME := $(shell uname -s)
ifeq ($(UNAME), Linux)
    LDFLAGS += -lm
endif

.PHONY: all test-safe clean

all: rowhammer_test

rowhammer_test: rowhammer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "[✓] Compilé : rowhammer_test"
	@echo "    Usage : sudo ./rowhammer_test --size 256 --iters 2000000 --time 30"
	@echo "    ATTENTION : ne jamais lancer sur une machine de production !"

# Test rapide et à faible risque (64MB, 100K iter, 5s max)
test-safe: rowhammer_test
	@echo "[!] Test Rowhammer court (64MB, 100K iter, 5s) — résultat non exhaustif"
	sudo ./rowhammer_test --size 64 --iters 100000 --time 5

clean:
	rm -f rowhammer_test rowhammer_test.dSYM
