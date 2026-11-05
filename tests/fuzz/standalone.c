/*
 * Replay driver for the fuzz targets, for compilers without libFuzzer.
 * Usage: fuzz_X [FILE | DIR]...   (a directory replays every file in it)
 * Each input is copied into a heap buffer of exactly its size, so ASan
 * catches a read one byte past the end, as it would under libFuzzer.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "fuzz.h"

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return -1; }
    size_t cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    size_t r;
    while (buf && (r = fread(buf + n, 1, cap - n, fp)) > 0) {
        n += r;
        if (n == cap) {
            uint8_t *b = realloc(buf, cap *= 2);
            if (!b) { free(buf); buf = NULL; }
            else buf = b;
        }
    }
    fclose(fp);
    if (!buf) { fprintf(stderr, "%s: out of memory\n", path); return -1; }
    uint8_t *exact = malloc(n ? n : 1);     /* exactly n bytes */
    if (!exact) { free(buf); return -1; }
    memcpy(exact, buf, n);
    free(buf);
    LLVMFuzzerTestOneInput(exact, n);
    free(exact);
    return 0;
}

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int run_path(const char *path, int *count) {
    struct stat st;
    if (stat(path, &st) < 0) { perror(path); return -1; }
    if (!S_ISDIR(st.st_mode)) {
        (*count)++;
        return run_file(path);
    }
    DIR *d = opendir(path);
    if (!d) { perror(path); return -1; }
    char **names = NULL;
    size_t nn = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char **m = realloc(names, (nn + 1) * sizeof(*names));
        if (!m) break;
        names = m;
        size_t l = strlen(path) + strlen(e->d_name) + 2;
        names[nn] = malloc(l);
        if (!names[nn]) break;
        snprintf(names[nn], l, "%s/%s", path, e->d_name);
        nn++;
    }
    closedir(d);
    qsort(names, nn, sizeof(*names), cmp);    /* deterministic order */
    int rc = 0;
    for (size_t i = 0; i < nn; i++) {
        if (run_path(names[i], count) < 0) rc = -1;
        free(names[i]);
    }
    free(names);
    return rc;
}

int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    int count = 0, rc = 0;
    for (int i = 1; i < argc; i++)
        if (run_path(argv[i], &count) < 0) rc = 1;
    fprintf(stderr, "%s: %d input%s replayed\n", argv[0], count, count == 1 ? "" : "s");
    return rc;
}
