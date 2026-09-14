# SQLite (vendored)

- Upstream: https://sqlite.org/
- Version: 3.50.4 (amalgamation)
- Source: https://sqlite.org/2025/sqlite-amalgamation-3500400.zip
- License: Public domain. SQLite ships no `LICENSE` file -- this is
  deliberate, not an omission on our part. See
  https://sqlite.org/copyright.html.
- Files: `sqlite3.c`, `sqlite3.h` -- copied verbatim, no local modifications.

The amalgamation zip also contains `shell.c` (the `sqlite3` command-line
shell) and `sqlite3ext.h` (the loadable-extension ABI). Neither is vendored:
this project does not build the CLI, and the build disables extension
loading outright (`SQLITE_OMIT_LOAD_EXTENSION`), so pulling those files in
would only leave a reader ruling out code that is never compiled.

SHA-256 of the two vendored files as fetched from the URL above:

```
e3f5d6901e7492af4a1fc8c4d745cae84c264942524c3fbfc02b82a5ca8818c8  sqlite3.c
abd1514e0351f79393d1be882830afdb40a8099e8257f311f0bfdf8486f11bea  sqlite3.h
```

## Build flags

`CMakeLists.txt` compiles `sqlite3.c` with a fixed set of
`target_compile_definitions`, each commented with its reason at the point
of use. `SQLITE_THREADSAFE=0` is the one to note here specifically: it is a
correctness decision for this project's single-threaded epoll reactor, not
a performance tuning knob, and must not be "fixed" back to a threadsafe
mode. `libcloak-common/tests/test_sqlite_link.c` asserts
`sqlite3_threadsafe() == 0` so a silent regression of that define is
caught by the test suite.

## Updating

Re-download `sqlite3.c` and `sqlite3.h` from the new release's amalgamation
zip at https://sqlite.org/download.html, update the version and digests
above, and run the full test suite. Do not patch the sources in place: this
project's `-Wall -Wextra` settings are suppressed for this target (`-w` in
`CMakeLists.txt`) precisely so the copy can stay verbatim.
