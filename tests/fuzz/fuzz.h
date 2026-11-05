/*
 * Shared declarations for the fuzz targets in tests/fuzz/.
 *
 * Each fuzz_*.c defines the two libFuzzer entry points. Built with
 * clang -fsanitize=fuzzer they run under libFuzzer (make fuzz); linked
 * with standalone.c instead they replay files and directories given on
 * the command line, which is how make test checks the seed corpus and the
 * committed crash reproducers with any compiler (gcc, Apple clang).
 */
#ifndef SIMPLEIDS_FUZZ_H
#define SIMPLEIDS_FUZZ_H

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif
