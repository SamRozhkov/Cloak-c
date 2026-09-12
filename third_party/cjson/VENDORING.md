# cJSON (vendored)

- Upstream: https://github.com/DaveGamble/cJSON
- Version: v1.7.19
- License: MIT (see `LICENSE`)
- Files: `cJSON.c`, `cJSON.h`, `LICENSE` — copied verbatim, no local modifications.

SHA-256 of the vendored files as fetched from
`https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.19/`:

```
298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d  cJSON.c
25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee  cJSON.h
a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c  LICENSE
```

## Updating

Re-download the three files at the new tag, update the version and digests
above, and run the full test suite. Do not patch the sources in place: this
project's `-Wall -Wextra` settings are suppressed for this target
(`-w` in `CMakeLists.txt`) precisely so the copy can stay verbatim.
