# SimpleIDS build
#
#   make            build ./SimpleIDS
#   make test       unit tests + pcap regression tests + evasion report
#                   + CLI tests (--test-rules, SIGHUP reload)
#                   + rule library test (one sample per rule, clean corpus)
#   make bench      throughput with 10 rules vs. all rules (Phase 4 acceptance)
#   make asan       build and run all tests with AddressSanitizer + UBSan
#   make pcaps      regenerate tests/pcaps from tests/regression/gen_pcaps.py
#   make run        build and capture live (sudo)
#   make clean
#
# Options: WERROR=1 adds -Werror, SAN=1 builds with sanitizers into build/asan.

CC      ?= cc
PYTHON  ?= python3

CFLAGS  ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wformat=2 -Iinclude -MMD -MP
LDLIBS  += -lpcap

# PCRE2 (8-bit): pkg-config, else pcre2-config, else the default paths.
PCRE2_CFLAGS := $(shell pkg-config --cflags libpcre2-8 2>/dev/null || pcre2-config --cflags 2>/dev/null)
PCRE2_LIBS   := $(shell pkg-config --libs libpcre2-8 2>/dev/null || pcre2-config --libs8 2>/dev/null || echo -lpcre2-8)
CFLAGS  += $(PCRE2_CFLAGS)
LDLIBS  += $(PCRE2_LIBS)

ifeq ($(WERROR),1)
CFLAGS  += -Werror
endif

ifeq ($(SAN),1)
BUILD   := build/asan
BIN     := $(BUILD)/SimpleIDS
SANFLAGS:= -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
CFLAGS  += $(SANFLAGS)
LDFLAGS += $(SANFLAGS)
else
BUILD   := build/release
BIN     := SimpleIDS
endif

LIB_SRC := src/util/bytes.c \
           src/util/siphash.c \
           src/util/digest.c \
           src/decode/decode.c \
           src/flow/flow.c \
           src/stream/stream.c \
           src/app/http/http.c \
           src/app/tls/tls.c \
           src/app/dns/dns.c \
           src/detect/mpm.c \
           src/detect/threshold.c \
           src/detect/rule_parse.c \
           src/detect/detect.c \
           src/anomaly/anomaly.c \
           src/output/output.c \
           src/core/engine.c
MAIN_SRC := src/core/main.c
TEST_SRC := $(wildcard tests/unit/*.c)

LIB_OBJ  := $(LIB_SRC:%.c=$(BUILD)/%.o)
MAIN_OBJ := $(MAIN_SRC:%.c=$(BUILD)/%.o)
TEST_OBJ := $(TEST_SRC:%.c=$(BUILD)/%.o)
UNIT_BIN := $(BUILD)/unit_tests

.PHONY: all test unit regression evasion cli library bench asan pcaps run clean

all: $(BIN)

$(BIN): $(LIB_OBJ) $(MAIN_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(UNIT_BIN): $(LIB_OBJ) $(TEST_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

unit: $(UNIT_BIN)
	./$(UNIT_BIN)

regression: $(BIN)
	$(PYTHON) tests/regression/run.py --bin ./$(BIN)

evasion: $(BIN)
	$(PYTHON) tests/evasion/report.py --bin ./$(BIN)

cli: $(BIN)
	$(PYTHON) tests/cli/test_cli.py --bin ./$(BIN)

library: $(BIN)
	$(PYTHON) tests/rules/test_library.py --bin ./$(BIN)

test: unit regression evasion cli library

bench: $(BIN)
	$(PYTHON) tests/bench/bench.py --bin ./$(BIN)

asan:
	$(MAKE) SAN=1 test

pcaps:
	$(PYTHON) tests/regression/gen_pcaps.py

run: $(BIN)
	sudo ./$(BIN)

clean:
	rm -rf build SimpleIDS

-include $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d) $(TEST_OBJ:.o=.d)
