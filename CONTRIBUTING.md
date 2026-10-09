# Contributing

## Before you start

1. Read [`AGENTS.md`](AGENTS.md). It is the mandatory engineering standard
   for this project (C++20 usage, C ABI design, ownership, thread safety,
   testing, ABI stability) and applies to human and automated contributors
   alike.
2. Check the [roadmap](README.md#-roadmap) and open issues to avoid
   duplicating work. For anything beyond a trivial fix, open an issue
   first to agree on the approach — especially for public API changes,
   which need explicit maintainer approval.

## Development setup

Requirements: a C++20 compiler (GCC or Clang), CMake, Protocol Buffers
compiler and C++ runtime. For the Rust example you additionally need a
Rust toolchain.

```bash
# Configure with tests enabled
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON

# Build
cmake --build build --parallel

# Test
ctest --test-dir build --output-on-failure
```

Both library modes must keep working:

```bash
cmake -S . -B build-shared -DLIBUSPMTP_BUILD_SHARED=ON
cmake --build build-shared --parallel
```

## What a complete change looks like

- [ ] Library builds (static and shared)
- [ ] `ctest` passes
- [ ] Sanitizer run is clean (ASan + UBSan; see below)
- [ ] Line coverage of `src/` stays at or above the threshold (see below);
      new behaviour is covered by the tests that come with it
- [ ] New behaviour has tests (`tests/`); public API changes have C and
      C++ consumer coverage where applicable
- [ ] No new compiler warnings
- [ ] No ABI break without explicit approval and versioning
- [ ] Public header still compiles as both C and C++
- [ ] Documentation updated (`README.md` API tables / examples as needed)
- [ ] New source files carry the Apache-2.0 header with
      `SPDX-License-Identifier: Apache-2.0`

Run the sanitizer configuration before submitting:

```bash
cmake -S . -B build-asan \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan --parallel
ASAN_OPTIONS=halt_on_error=1:detect_leaks=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-asan --output-on-failure
```

## Measuring test coverage

The library can be instrumented for gcov; the `coverage` target reports line
coverage of `src/` (generated protobuf code excluded) and fails below
`LIBUSPMTP_COVERAGE_MIN_LINES` (default 70 %). It needs `gcovr`.

```bash
cmake -S . -B build-cov \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON \
    -DLIBUSPMTP_COVERAGE=ON
cmake --build build-cov --parallel
ctest --test-dir build-cov --output-on-failure
cmake --build build-cov --target coverage
```

## Verifying the examples end to end

If your change touches the library, the examples, or the transport,
prove it against a real agent with the compose demo:

```bash
docker compose -f test/compose.yml up --build
```

All three example services (C, C++, Rust) must print the baseline
(`Device.LocalAgent.`, `Device.UnixDomainSockets.`, `Device.DeviceInfo.`)
fetched live from the agent. If a rebuild looks suspiciously instant
(everything CACHED), rebuild with `--no-cache` — stale BuildKit cache
has bitten before.

## Pull request guidance

- Keep pull requests focused: one change per PR, no unrelated refactoring
  mixed with functional changes.
- Make the smallest coherent change: small diff → build → test → inspect.
- Never remove or weaken a test to make a change pass; never disable
  warnings or sanitizers to hide failures.
- Describe observable behaviour change, test evidence, and any ABI impact.
- Security-sensitive reports do not belong in issues or PRs — see
  [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under
the Apache-2.0 license. New files must include the project license
header (see any existing source file for the exact text).
