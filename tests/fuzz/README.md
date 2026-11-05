# Fuzz targets

One libFuzzer target per parser that reads untrusted input, plus the whole
pipeline:

| target   | input                                   | code under test                          |
|----------|-----------------------------------------|------------------------------------------|
| `decode` | one captured frame, every link type     | `src/decode/`                            |
| `http`   | an HTTP request / URI / form / chunked  | `src/app/http/` (parse + normalization)  |
| `tls`    | the start of a client TLS stream        | `src/app/tls/` (ClientHello, JA3, JA4)   |
| `dns`    | a DNS message                           | `src/app/dns/`                           |
| `rules`  | a rules file                            | `src/detect/` (parse, compile, evaluate) |
| `engine` | a sequence of frames (see the file)     | decode → flow → reassembly → app → detect |
| `config` | a config file                           | `src/core/settings.c`                    |

```
make fuzz                         # every target for 60 s (clang + libFuzzer)
make fuzz FUZZ_TARGETS=http FUZZ_TIME=3600 FUZZ_JOBS=4
make fuzz-replay                  # seeds + regressions, any compiler (part of make test)
```

* Seeds are generated from the repository (`make_seeds.py`: regression
  pcaps, rule-library samples, rule files, `etc/simpleids.conf`); the growing
  corpus lives in `build/fuzz/corpus/<target>/`, crashes in
  `build/fuzz/crash-<target>-*`.
* A crash is a bug: fix it, add a unit test that reproduces it
  (`tests/unit/`), and commit the crashing input to
  `tests/fuzz/regressions/<target>/` so `make test` replays it forever.
* `standalone.c` replays files without libFuzzer, so gcc and Apple clang
  builds (and the ASan CI jobs) run the same inputs.
* CI: `fuzz-smoke` runs each target for 45 s on every push;
  `.github/workflows/fuzz.yml` runs a long campaign nightly and keeps the
  corpus and the accumulated CPU-hours in the Actions cache.
