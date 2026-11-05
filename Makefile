# SimpleIDS build
#
#   make            build ./SimpleIDS
#   make test       unit tests + pcap regression tests + evasion report
#                   + CLI tests (--test-rules, SIGHUP reload)
#                   + rule library test (one sample per rule, clean corpus)
#   make fuzz       run every libFuzzer target for FUZZ_TIME seconds (clang)
#   make fuzz-replay  run the fuzz targets over seeds + crash reproducers
#                   (part of make test; works with any compiler)
#   make hardening  check PIE / RELRO / NX / stack protector / FORTIFY
#   make bench      throughput with 10 rules vs. all rules (Phase 4 acceptance)
#   make asan       build and run all tests with AddressSanitizer + UBSan
#   make pcaps      regenerate tests/pcaps from tests/regression/gen_pcaps.py
#   make run        build and capture live (sudo)
#   make clean
#
# Options: WERROR=1 adds -Werror, SAN=1 builds with sanitizers into build/asan,
#          HARDEN=0 leaves out the hardening flags, FUZZ=1 is the libFuzzer build.

SHELL   := /bin/bash
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

ifeq ($(FUZZ),1)
# libFuzzer build (clang): instrumented library objects, see make fuzz.
CC      := clang
BUILD   := build/fuzz
BIN     := $(BUILD)/SimpleIDS
SANFLAGS:= -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
CFLAGS  += $(SANFLAGS) -fsanitize=fuzzer-no-link -DSIMPLEIDS_FUZZING
LDFLAGS += $(SANFLAGS)
else ifeq ($(SAN),1)
BUILD   := build/asan
BIN     := $(BUILD)/SimpleIDS
SANFLAGS:= -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
CFLAGS  += $(SANFLAGS)
LDFLAGS += $(SANFLAGS)
else
BUILD   := build/release
BIN     := SimpleIDS
endif

# Hardening (on by default; HARDEN=0 turns it off). Optional flags are
# probed once, so older compilers and Apple clang just skip what they lack.
HARDEN  ?= 1
UNAME_S := $(shell uname -s)
probe    = $(shell $(CC) -Werror $(1) -c -x c /dev/null -o /dev/null >/dev/null 2>&1 && echo $(1))
ifeq ($(HARDEN),1)
HARDEN_OPT := $(call probe,-fstack-clash-protection) $(call probe,-fcf-protection=full)
CFLAGS  += -fstack-protector-strong -fPIE $(HARDEN_OPT)
ifeq ($(UNAME_S),Linux)
LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
endif
# _FORTIFY_SOURCE needs optimization and gets in the way of the
# sanitizers' interceptors; distributions often predefine it, hence -U.
ifeq ($(filter 1,$(SAN) $(FUZZ)),)
CFLAGS  += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
endif
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
           src/core/engine.c \
           src/core/settings.c \
           src/core/sandbox.c
MAIN_SRC := src/core/main.c
TEST_SRC := $(wildcard tests/unit/*.c)
FUZZ_TARGETS := decode http tls dns rules engine config
FUZZ_TIME    ?= 60
FUZZ_JOBS    ?= 1
FUZZ_SEEDS   := build/fuzz-seeds

LIB_OBJ  := $(LIB_SRC:%.c=$(BUILD)/%.o)
MAIN_OBJ := $(MAIN_SRC:%.c=$(BUILD)/%.o)
TEST_OBJ := $(TEST_SRC:%.c=$(BUILD)/%.o)
UNIT_BIN := $(BUILD)/unit_tests

FUZZ_OBJ    := $(FUZZ_TARGETS:%=$(BUILD)/tests/fuzz/fuzz_%.o)
FUZZ_BINS   := $(FUZZ_TARGETS:%=$(BUILD)/fuzz_%)
REPLAY_BINS := $(FUZZ_TARGETS:%=$(BUILD)/replay_%)

.PHONY: all test unit regression evasion cli library bench asan pcaps run clean hardening \
        fuzz fuzz-build fuzz-replay fuzz-seeds

all: $(BIN)

$(BIN): $(LIB_OBJ) $(MAIN_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(UNIT_BIN): $(LIB_OBJ) $(TEST_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# libFuzzer binaries (make FUZZ=1 fuzz-build) and replay binaries that
# run the same targets over files with any compiler (standalone.c).
$(BUILD)/fuzz_%: $(LIB_OBJ) $(BUILD)/tests/fuzz/fuzz_%.o
	$(CC) $(LDFLAGS) -fsanitize=fuzzer -o $@ $^ $(LDLIBS)

$(BUILD)/replay_%: $(LIB_OBJ) $(BUILD)/tests/fuzz/fuzz_%.o $(BUILD)/tests/fuzz/standalone.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

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

fuzz-seeds:
	@rm -rf $(FUZZ_SEEDS)
	@$(PYTHON) tests/fuzz/make_seeds.py $(FUZZ_SEEDS)

# Every fuzz target over its seeds and committed crash reproducers.
fuzz-replay: $(REPLAY_BINS) fuzz-seeds
	@for t in $(FUZZ_TARGETS); do \
	    ./$(BUILD)/replay_$$t $(FUZZ_SEEDS)/$$t $$(ls -d tests/fuzz/regressions/$$t 2>/dev/null) \
	        || exit 1; \
	done

fuzz-build:
	$(MAKE) FUZZ=1 $(FUZZ_TARGETS:%=build/fuzz/fuzz_%)

# make fuzz [FUZZ_TIME=seconds per target] [FUZZ_TARGETS="http tls"]
# The corpus grows in build/fuzz/corpus/<target>; crashes are written to
# build/fuzz/crash-<target>-*. Needs clang with libFuzzer.
fuzz: fuzz-build fuzz-seeds
	@for t in $(FUZZ_TARGETS); do \
	    mkdir -p build/fuzz/corpus/$$t; \
	    dict=; [ -f tests/fuzz/$$t.dict ] && dict=-dict=tests/fuzz/$$t.dict; \
	    echo "== fuzz_$$t for $(FUZZ_TIME)s (log: build/fuzz/fuzz_$$t.log)"; \
	    if ./build/fuzz/fuzz_$$t -max_total_time=$(FUZZ_TIME) -timeout=10 -rss_limit_mb=2048 \
	        -close_fd_mask=3 -print_final_stats=1 $(if $(filter-out 1,$(FUZZ_JOBS)),-fork=$(FUZZ_JOBS)) \
	        -artifact_prefix=build/fuzz/crash-$$t- $$dict \
	        build/fuzz/corpus/$$t $(FUZZ_SEEDS)/$$t $$(ls -d tests/fuzz/regressions/$$t 2>/dev/null) \
	        > build/fuzz/fuzz_$$t.log 2>&1; then \
	        grep -E '^(#[0-9]+.*(DONE|cov:)|stat::(number_of_executed_units|peak_rss_mb))' \
	            build/fuzz/fuzz_$$t.log | grep -v NEW_FUNC | tail -n 3 || true; \
	    else \
	        tail -n 80 build/fuzz/fuzz_$$t.log; exit 1; \
	    fi; \
	done

# PIE, RELRO, NX stack, stack protector, FORTIFY in the built binary.
hardening: $(BIN)
	$(PYTHON) tests/hardening/check.py --bin ./$(BIN) $(if $(filter 1,$(SAN) $(FUZZ)),--sanitizer)

test: unit regression evasion cli library fuzz-replay $(if $(filter 1,$(HARDEN)),hardening)

.SECONDARY: $(FUZZ_OBJ) $(BUILD)/tests/fuzz/standalone.o

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

-include $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d) $(TEST_OBJ:.o=.d) $(FUZZ_OBJ:.o=.d)
