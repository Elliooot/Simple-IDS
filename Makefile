# SimpleIDS build
#
#   make            build ./SimpleIDS
#   make test       unit tests + pcap regression tests
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
           src/decode/decode.c \
           src/app/http/http.c \
           src/app/tls/tls.c \
           src/detect/rules.c \
           src/anomaly/anomaly.c \
           src/output/output.c \
           src/core/engine.c
MAIN_SRC := src/core/main.c
TEST_SRC := $(wildcard tests/unit/*.c)

LIB_OBJ  := $(LIB_SRC:%.c=$(BUILD)/%.o)
MAIN_OBJ := $(MAIN_SRC:%.c=$(BUILD)/%.o)
TEST_OBJ := $(TEST_SRC:%.c=$(BUILD)/%.o)
UNIT_BIN := $(BUILD)/unit_tests

.PHONY: all test unit regression asan pcaps run clean

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

test: unit regression

asan:
	$(MAKE) SAN=1 test

pcaps:
	$(PYTHON) tests/regression/gen_pcaps.py

run: $(BIN)
	sudo ./$(BIN)

clean:
	rm -rf build SimpleIDS

-include $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d) $(TEST_OBJ:.o=.d)
