/* Fuzz target: the INI config file parser and every setting's validator. */
#include <string.h>

#include "fuzz.h"
#include "simpleids/settings.h"

static settings_t s;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    settings_defaults(&s);
    (void)settings_parse(&s, "fuzz.conf", data, size, NULL, NULL);
    /* Whatever was accepted is bounded and terminated. */
    if (s.nrule_paths < 0 || s.nrule_paths > SETTINGS_MAX_RULES ||
        s.nvars < 0 || s.nvars > SETTINGS_MAX_VARS ||
        !memchr(s.log, 0, sizeof(s.log)) || !memchr(s.filter, 0, sizeof(s.filter)) ||
        !memchr(s.user, 0, sizeof(s.user)) || !memchr(s.interface, 0, sizeof(s.interface)) ||
        s.engine.flow.max_flows == 0 || s.engine.stream.depth == 0 || s.log_max_files == 0)
        __builtin_trap();
    for (int i = 0; i < s.nrule_paths; i++)
        if (!memchr(s.rule_paths[i], 0, SETTINGS_PATH_MAX) || !s.rule_paths[i][0]) __builtin_trap();
    return 0;
}
