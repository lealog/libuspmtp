<div align="center">

# libuspmtp

### A modern C++20 USP (TR-369) MTP protocol library

**Talk to USP Agents through a safe, stable, C-compatible API.**

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](#)
[![C API](https://img.shields.io/badge/API-C%20ABI-informational.svg)](#)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#)
[![Build](https://github.com/kartikg33/libuspmtp/actions/workflows/build.yml/badge.svg)](https://github.com/kartikg33/libuspmtp/actions/workflows/build.yml)
[![Tests](https://github.com/kartikg33/libuspmtp/actions/workflows/test.yml/badge.svg)](https://github.com/kartikg33/libuspmtp/actions/workflows/test.yml)

<br />

**C++20 implementation · C ABI · Static & Shared Libraries · USP / TR-369 · MTP / Unix Domain Sockets**

<br />

[Features](#-features) ·
[API](#-api-status) ·
[Quick Start](#-quick-start) ·
[Build](#-build) ·
[Examples](#-examples) ·
[Architecture](#-architecture) ·
[Contributing](#-contributing)

</div>

---

## ✨ Overview

**libuspmtp** is a modern C++20 library for communicating with **USP Agents** implementing the Broadband Forum **USP (TR-369) MTP** protocol.

It provides a clean controller API for operations such as:

- `GET`
- `GET_SUPPORTED_DM`
- `GET_INSTANCES`
- `SET`
- `ADD`
- `DELETE`
- `OPERATE`
- `REGISTER`
- `GET_SUPPORTED_PROTOCOL`
- `SUBSCRIBE`
- `SUBSCRIBE_AND_GET`

The library is designed around a simple principle:

> **Modern C++20 internally. Stable C ABI externally. Maximum compatibility with your code.**

The implementation uses modern C++ ownership, RAII, concurrency primitives, and asynchronous facilities while exposing a conservative C-compatible API that can be consumed by C, modern C++, legacy C/C++ applications, and other FFI-supported languages such as Rust.

---

## 🚀 Why libuspmtp?

USP controllers frequently need to live inside long-running embedded systems, network services, management applications, and existing C/C++ codebases.

libuspmtp is designed for those environments.

### Modern C++20

Built using modern C++20 facilities with a focus on:

- RAII
- Explicit ownership
- Strong lifetime guarantees
- Type safety
- Structured concurrency
- Safe asynchronous operations
- C++20 coroutines where appropriate

### Stable C ABI

The public API is exposed through a C-compatible header.

That means the same library can be consumed by:
- C
- C++20
- Legacy C++
- Other languages with C FFI support, e.g. Rust

without exposing C++ implementation details.

### Static or shared

Build and distribute the library as either a static library or a shared (dynamic) library depending on the needs of your application.

### Designed for embedded and systems software

The library is designed with long-running processes, constrained systems, asynchronous events, deterministic cleanup, and predictable resource ownership in mind.

---

## 📦 Features

| Feature | Status |
|---|:---:|
| USP GET | ✅ |
| USP GET_MANY | ✅ |
| USP SET | ✅ |
| USP SET_MANY | ✅ |
| USP OPERATE | ✅ |
| USP SUBSCRIBE_AND_GET | ✅ |
| USP SUBSCRIBE_MANY_AND_GET | ✅ |
| USP REGISTER (as a USP Service, with DEREGISTER, GET_SUPPORTED_DM, GET, GET_INSTANCES, SET, ADD, DELETE, OPERATE served and NOTIFY sent) | ✅ |
| USP ADD | ✅ |
| USP DELETE | ✅ |
| USP GET_SUPPORTED_DM | ✅ |
| USP GET_INSTANCES | ✅ |
| USP GET_SUPPORTED_PROTOCOL | ✅ |
| C-compatible public API | ✅ |
| C++20 implementation | ✅ |
| Static library | ✅ |
| Shared library | ✅ |
| C examples | ✅ |
| C++ examples | ✅ |
| Rust examples | ✅ |
| Sanitizer builds | ✅ |
| Package-manager distribution | 🚧 |

> **Legend:** ✅ Implemented · 🚧 Planned / In progress · ❌ Not supported

---

# 📚 API Status

| API | Status | Description |
|---|:---:|---|
| `usp_controller_new()` | ✅ | Create a controller |
| `usp_controller_free()` | ✅ | Destroy a controller and release its resources |
| `usp_controller_set_timeout()` | ✅ | Configure operation timeout |
| `usp_controller_set_password()` | ✅ | Password for the agent's authenticated UDS sockets |
| `usp_controller_get()` | ✅ | Retrieve parameters |
| `usp_controller_get_many()` | ✅ | Retrieve multiple paths |
| `usp_controller_set()` | ✅ | Update a parameter |
| `usp_controller_set_many()` | ✅ | Update multiple parameters |
| `usp_controller_operate()` | ✅ | Execute a USP command |
| `usp_controller_subscribe_and_get()` | ✅ | Subscribe and retrieve initial state |
| `usp_controller_subscribe_many_and_get()` | ✅ | Create multiple subscriptions and retrieve state |
| `usp_controller_last_error()` | ✅ | Retrieve the last human-readable error |
| `usp_error_is_vendor_defined()` | ✅ | Test whether a USP error code is vendor-defined |
| `usp_controller_register()` | ❌ | Registering a data model makes the app a USP Service: use `usp_service_*` |
| `usp_service_new()` / `usp_service_free()` | ✅ | A USP Service that publishes a data model through the broker |
| `usp_service_add_object()` / `_add_param()` / `_add_command()` / `_add_event()` | ✅ | Describe the published data model |
| `usp_service_set_callbacks()` | ✅ | Callbacks that own the values (get, instances, set, add, delete, operate) |
| `usp_service_start()` / `usp_service_stop()` | ✅ | Register the roots with the broker; deregister and disconnect |
| `usp_service_value_changed()` / `_object_created()` / `_object_deleted()` / `_event()` | ✅ | Notify the broker's subscriptions |
| `usp_controller_add()` | ✅ | Create object instance |
| `usp_controller_delete()` | ✅ | Delete object instance |
| `usp_controller_get_supported_dm()` | ✅ | Query supported data model |
| `usp_controller_get_instances()` | ✅ | Query object instances |
| `usp_controller_get_supported_protocol()` | ✅ | Query supported USP protocol |

APIs marked as planned currently return `USP_ERR_USP`.

---

# ⚡ Quick Start

## C

The public API is intentionally C-compatible.

```c
#include "libuspmtp.h"
#include <stdio.h>

int main(void)
{
    UspControllerHandle* controller =
        usp_controller_new(
            "/var/run/usp/broker_agent_path",
            "proto::my-app",
            "proto::api-gateway",
            10
        );

    if (controller == NULL) {
        return 1;
    }

    char value[256];

    const int rc =
        usp_controller_get(
            controller,
            "Device.DeviceInfo.SerialNumber",
            value,
            sizeof(value)
        );

    if (rc == USP_OK) {
        printf("SerialNumber=%s\n", value);
    } else {
        char error[256];

        usp_controller_last_error(
            controller,
            error,
            sizeof(error)
        );

        fprintf(
            stderr,
            "USP error (%d): %s\n",
            rc,
            error
        );
    }

    usp_controller_free(controller);

    return 0;
}
```

---

## C++20

The same C API can be consumed naturally from C++20.

```cpp
#include "libuspmtp.h"

#include <array>
#include <iostream>
#include <memory>

int main()
{
    using ControllerPtr =
        std::unique_ptr<
            UspControllerHandle,
            decltype(&usp_controller_free)
        >;

    ControllerPtr controller{
        usp_controller_new(
            "/var/run/usp/broker_agent_path",
            "proto::my-cpp-app",
            "proto::api-gateway",
            10
        ),
        &usp_controller_free
    };

    if (!controller) {
        return 1;
    }

    std::array<char, 256> value{};

    const auto rc =
        usp_controller_get(
            controller.get(),
            "Device.DeviceInfo.SerialNumber",
            value.data(),
            value.size()
        );

    if (rc == USP_OK) {
        std::cout
            << "SerialNumber="
            << value.data()
            << '\n';

        return 0;
    }

    std::array<char, 256> error{};

    usp_controller_last_error(
        controller.get(),
        error.data(),
        error.size()
    );

    std::cerr
        << "USP error ("
        << rc
        << "): "
        << error.data()
        << '\n';

    return 1;
}
```

---

## Publishing a data model (USP Service)

An application that owns part of the data model is a USP Service: it connects to the
broker's *controller* socket, registers its roots, and answers what the broker routes to it.
The library does the protocol; the application describes the schema and supplies callbacks
that own the values (see `usp_service_*` in `libuspmtp.h`).

```c
#include "libuspmtp.h"

static int my_get(void *ud, const char *obj_path, char *out, size_t out_len) {
    if (strcmp(obj_path, "Device.X_EXAMPLE_App.") != 0) return USP_ERR_NOT_FOUND;
    snprintf(out, out_len, "PARAM\tVersion\t1.0\nPARAM\tEnable\ttrue\n");
    return USP_OK;
}

int main(void)
{
    UspServiceHandle *svc = usp_service_new("/var/run/usp/broker_controller_path", "proto::my-app", "", 10);
    usp_service_add_object(svc, "Device.X_EXAMPLE_App.", 0, USP_OBJ_ACCESS_READ_ONLY, NULL);
    usp_service_add_param(svc, "Device.X_EXAMPLE_App.", "Version", USP_PARAM_ACCESS_READ_ONLY, USP_PARAM_TYPE_STRING);
    usp_service_add_param(svc, "Device.X_EXAMPLE_App.", "Enable", USP_PARAM_ACCESS_READ_WRITE, USP_PARAM_TYPE_BOOLEAN);

    UspServiceCallbacks cb = {0};
    cb.get = my_get;                       /* set, add, del, operate, instances are optional */
    usp_service_set_callbacks(svc, &cb);

    const char *roots[] = {"Device.X_EXAMPLE_App."};
    char result[256];
    if (usp_service_start(svc, roots, 1, 0, result, sizeof result) == USP_OK)
        printf("%s", result);              /* REGISTERED\tDevice.X_EXAMPLE_App.\n */

    /* ... the broker now routes Get/Set/Operate for that object to the callbacks ... */
    usp_service_value_changed(svc, "Device.X_EXAMPLE_App.Enable", "false");   /* Notify matching subscriptions */

    usp_service_free(svc);                 /* deregisters and disconnects */
    return 0;
}
```

A C++ program uses `usp::UspService` (`service.hpp`) with `std::function` handlers instead.

## Rust

Rust consumers use the same C ABI through a small `extern "C"` declaration.
The full working version (baseline GET, subscribe, re-GET loop, no external
crates) lives in [`examples/rust/`](examples/rust/), which links
`libuspmtp.so` dynamically.

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// Opaque handle; see UspControllerHandle in libuspmtp.h.
#[repr(C)]
struct UspControllerHandle {
    _private: [u8; 0],
}

const USP_OK: c_int = 0;

// libuspmtp.so (CMake OUTPUT_NAME "uspmtp").
// kind = "dylib" forces dynamic linking and fails the build if only a
// static archive is available.
#[link(name = "uspmtp", kind = "dylib")]
extern "C" {
    fn usp_controller_new(
        socket_path: *const c_char,
        app_endpoint_id: *const c_char,
        agent_endpoint_id: *const c_char,
        timeout_secs: u64,
    ) -> *mut UspControllerHandle;
    fn usp_controller_free(handle: *mut UspControllerHandle);
    fn usp_controller_get(
        handle: *mut UspControllerHandle,
        path: *const c_char,
        out_value: *mut c_char,
        out_value_len: usize,
    ) -> c_int;
    fn usp_controller_last_error(
        handle: *const UspControllerHandle,
        out_error: *mut c_char,
        out_error_len: usize,
    ) -> c_int;
}

fn main() {
    let socket = CString::new("/var/run/usp/broker_agent_path").unwrap();
    let app = CString::new("proto::my-rust-app").unwrap();
    let agent = CString::new("proto::api-gateway").unwrap();
    let path = CString::new("Device.DeviceInfo.SerialNumber").unwrap();

    // SAFETY: all pointers borrow live CStrings.
    let controller = unsafe {
        usp_controller_new(socket.as_ptr(), app.as_ptr(), agent.as_ptr(), 10)
    };
    assert!(!controller.is_null());

    let mut value = vec![0 as c_char; 256];
    // SAFETY: controller is valid; value is 256 writable bytes.
    let rc = unsafe {
        usp_controller_get(controller, path.as_ptr(), value.as_mut_ptr(), value.len())
    };

    if rc == USP_OK {
        // SAFETY: on success the library NUL-terminates the buffer.
        let serial = unsafe { CStr::from_ptr(value.as_ptr()) };
        println!("SerialNumber={}", serial.to_string_lossy());
    } else {
        let mut error = vec![0 as c_char; 256];
        // SAFETY: controller is valid; error is 256 writable bytes.
        unsafe { usp_controller_last_error(controller, error.as_mut_ptr(), error.len()) };
        let msg = unsafe { CStr::from_ptr(error.as_ptr()) };
        eprintln!("USP error ({rc}): {}", msg.to_string_lossy());
    }

    // SAFETY: the owned handle is freed exactly once.
    unsafe { usp_controller_free(controller) };
}
```

Build against the shared library, then run with Cargo (offline — the
example has no external crates):

```bash
cmake -S . -B build-shared \
    -DCMAKE_BUILD_TYPE=Release \
    -DLIBUSPMTP_BUILD_SHARED=ON
cmake --build build-shared --parallel
cmake --install build-shared --prefix /usr/local

LIBUSPMTP_LIB_DIR=/usr/local/lib cargo run --release \
    --manifest-path examples/rust/Cargo.toml
```

---

# 🛠️ Build

## Requirements

### Required

- C++20 compiler
- CMake
- Official Protocol Buffers compiler and C++ runtime
- A supported platform/compiler combination

### Required for the Rust example only

- Rust toolchain (the example uses only the standard library, so it builds offline)
- A shared library build (`-DLIBUSPMTP_BUILD_SHARED=ON`, provides `libuspmtp.so`)

### Supported compilers

| Compiler | Status |
|---|:---:|
| GCC (CI: `ubuntu-latest`) | ✅ |
| Clang (CI: sanitizer job) | ✅ |
| MSVC | ❌ Not tested |

> **Legend:** ✅ Built in CI · ❌ Not covered by CI

---

## Configure

```bash
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release
```

## Build

```bash
cmake --build build --parallel
```

## Run tests

```bash
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON

cmake --build build --parallel

ctest --test-dir build --output-on-failure
```

---

# 📦 Static Library

Configure a static build:

```bash
cmake -S . -B build-static \
    -DCMAKE_BUILD_TYPE=Release \
    -DLIBUSPMTP_BUILD_SHARED=OFF
```

Build:

```bash
cmake --build build-static --parallel
```

The resulting static archive (`libuspmtp.a`) will be available under the project's configured library output directory.

---

# 🔗 Shared Library

Configure a shared build:

```bash
cmake -S . -B build-shared \
    -DCMAKE_BUILD_TYPE=Release \
    -DLIBUSPMTP_BUILD_SHARED=ON
```

Build:

```bash
cmake --build build-shared --parallel
```

This produces the versioned shared library (`libuspmtp.so.0.1.0` with
`libuspmtp.so.0` / `libuspmtp.so` symlinks; CMake `OUTPUT_NAME uspmtp`).

---

# 🧩 CMake Integration

Once installed (`cmake --install <build-dir> --prefix <prefix>`), applications
can consume the library using a normal CMake package:

```cmake
find_package(libuspmtp CONFIG REQUIRED)

target_link_libraries(
    my_application
    PRIVATE
        libuspmtp::libuspmtp
)
```

---

# 💡 Examples

Each example is a standalone application that demonstrates the same flow:

1. `GET` the baseline paths (`Device.LocalAgent.`, `Device.UnixDomainSockets.`,
   `Device.DeviceInfo.`) and print the returned parameters.
2. `SUBSCRIBE_AND_GET` on `Device.DeviceInfo.` for ValueChange notifications.
3. On each notification, re-`GET` the baseline paths and print the update.

| Example | Directory | Linking |
|---|---|---|
| C | [`examples/c/`](examples/c/) | Static (`libuspmtp.a`) |
| C++ | [`examples/cpp/`](examples/cpp/) | Static (`libuspmtp.a`) |
| Rust (std only, no crates) | [`examples/rust/`](examples/rust/) | Dynamic (`libuspmtp.so`) |

Build one Docker image per example and run all three against the same
OB-USPA agent over a shared UDS socket:

```bash
docker compose -f test/compose.yml up --build
```

Each service prints the fetched baseline values to the console, so the
output doubles as a live correctness check against the agent's data model
(e.g. `Device.LocalAgent.EndpointID == "proto::api-gateway"`).

See [`test/compose.yml`](test/compose.yml) for the full setup.

---

# 📁 Project Layout

```text
libuspmtp/
├── AGENTS.md
├── README.md
├── CMakeLists.txt
│
├── cmake/
│   └── libuspmtpConfig.cmake.in
│
├── include/
│   └── libuspmtp.h
│
├── src/
│   ├── client.cpp / client.hpp
│   ├── transport.cpp / transport.hpp
│   ├── usp_proto.cpp / usp_proto.hpp
│   └── libuspmtp.cpp
│
├── proto/
│   ├── usp-msg-1-5.proto
│   └── usp-record-1-5.proto
│
├── specification/
│
├── tests/
│   ├── test_proto.cpp
│   ├── test_transport.cpp
│   └── test_client.cpp
│
├── test/
│   └── compose.yml
│
├── examples/
│   ├── c/
│   ├── cpp/
│   └── rust/
│
└── .github/
    └── workflows/
```

The `include/` directory contains the public API.

Internal C++ implementation details must not leak into the public C header.

---

# 🏗️ Architecture

libuspmtp is deliberately split into two layers.

```text
┌─────────────────────────────────────────────────────────┐
│                    Application                          │
│                                                         │
│         C / C++ / Rust application over C FFI           │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Public C API                           │
│                                                         │
│              libuspmtp.h                         │
└───────────────────────────┬─────────────────────────────┘
                            │
                     Stable C ABI
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  C++20 Core                             │
│                                                         │
│   RAII · Ownership · Concurrency · Coroutines           │
│   Protocol · Transport · Callbacks · Error Handling     │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Message Transfer Transport                 │
│                                                         │
│                    UDS / ...                             │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                    USP Agent                            │
│                                                         │
│                  TR-369 / USP                           │
└─────────────────────────────────────────────────────────┘
```

The public ABI intentionally exposes opaque handles and C-compatible data structures.

Internally, the implementation is free to use modern C++20 abstractions without coupling consumers to C++ ABI details.

---

# 🔒 Memory & Thread Safety

Memory safety and deterministic ownership are core design requirements.

The implementation follows modern C++ practices including:

- RAII
- `std::unique_ptr`
- `std::shared_ptr` where genuinely required
- Explicit ownership
- Explicit lifetime management
- `std::jthread`
- `std::stop_token`
- C++20 synchronization primitives
- C++20 coroutines where appropriate
- Sanitizer-friendly code

C++ exceptions never cross the public C ABI.

Asynchronous operations must have explicit ownership, cancellation, and shutdown semantics.

For the complete engineering standard, see [`AGENTS.md`](AGENTS.md).

---

# 🌐 Transport

The initial transport implementation uses **Unix Domain Sockets (UDS)**.

Typical deployments may communicate with a USP Agent through a local broker or USP transport endpoint.

Example:

```text
libuspmtp
       │
       │ UDS
       ▼
USP Message Broker
       │
       ▼
USP Agent
```

Additional transports may be added in the future without changing the core controller API.

---

# 📖 Usage

## Controller creation

```c
UspControllerHandle* controller =
    usp_controller_new(
        "/var/run/usp/broker_agent_path",
        "proto::my-app",
        "proto::api-gateway",
        10
    );
```

The controller configuration includes:

| Parameter | Description |
|---|---|
| `socket_path` | USP transport socket |
| `app_endpoint_id` | Controller endpoint identifier |
| `agent_endpoint_id` | Target USP Agent endpoint identifier |
| `timeout` | Request timeout |

---

## GET

Retrieve parameters from the Agent:

```c
usp_controller_get(
    controller,
    "Device.DeviceInfo.SerialNumber",
    buffer,
    sizeof(buffer)
);
```

---

## SET

Update a parameter:

```c
usp_controller_set(
    controller,
    "Device.WiFi.SSID.1.SSID",
    "MyNetwork"
);
```

---

## OPERATE

Execute an operation:

```text
Device.IP.Diagnostics.IPPing()
```

with operation arguments such as:

```text
Host = 8.8.8.8
```

---

## SUBSCRIBE

Register for USP notification events.

The library supports subscription workflows including:

```text
SUBSCRIBE_AND_GET
SUBSCRIBE_MANY_AND_GET
```

with notification types such as:

```text
Value Change
Object Creation
Object Deletion
```

---

# 🧪 Testing

Run the complete test suite with:

```bash
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON

cmake --build build --parallel

ctest \
    --test-dir build \
    --output-on-failure
```

The test suite covers:

- Public API behavior
- Error handling
- Ownership
- Object lifetime
- Transport behavior
- USP operations
- Callbacks
- Asynchronous operations
- Concurrency
- Shutdown
- C ABI compatibility
- C++ integration

---

# 🧰 Sanitizers

Sanitizer builds are strongly recommended during development.
There are no dedicated CMake options; pass sanitizer flags through the
standard variables (this mirrors the CI sanitizer job):

Example configuration (ASan + UBSan with Clang):

```bash
cmake -S . -B build-asan \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBUSPMTP_BUILD_TESTS=ON \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
```

Then:

```bash
cmake --build build-asan --parallel

ASAN_OPTIONS=halt_on_error=1:detect_leaks=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest \
    --test-dir build-asan \
    --output-on-failure
```

ThreadSanitizer should be used where supported (substitute
`-fsanitize=thread` for the flags above; do not combine TSan with ASan).

---

# 📊 USP Error Codes

The library exposes USP error information through its public error API.

| Code | Name | Applicability | Description |
|---:|---|---|---|
| 7000 | Message failed | Error Message | General failure described by the associated error message. |
| 7001 | Message not supported | Error Message | The target endpoint did not understand the message. |
| 7002 | Request denied | Error Message | The target endpoint cannot or will not process the request. |
| 7003 | Internal error | Error Message | Internal hardware or software failure. |
| 7004 | Invalid arguments | Error Message | Invalid values were supplied in the USP message. |
| 7005 | Resources exceeded | Error Message | Memory or processing resources were insufficient. |
| 7006 | Permission denied | Error Message | The source endpoint is not authorized to perform the action. |
| 7007 | Invalid configuration | Error Message | Processing the request would result in an invalid configuration. |
| 7008 | Invalid path syntax | `requested_path` | The supplied path syntax was not understood. |
| 7009 | Parameter action failed | SET | A parameter update failed. |
| 7010 | Unsupported parameter | ADD, SET | The requested parameter does not exist. |
| 7011 | Invalid type | ADD, SET | The supplied value has an invalid type. |
| 7012 | Invalid value | ADD, SET | The supplied value is outside the permitted range. |
| 7013 | Non-writable parameter | ADD, SET | The parameter cannot be modified. |
| 7014 | Value conflict | ADD, SET | The requested value conflicts with another configuration value. |
| 7015 | Operation error | ADD, SET, DELETE | General object operation failure. |
| 7016 | Object does not exist | ADD, SET | The requested object does not exist. |
| 7017 | Object could not be created | ADD | Object creation failed. |
| 7018 | Object is not a table | ADD | The requested path is not a multi-instance object. |
| 7019 | Object is not creatable | ADD | The requested object cannot be created. |
| 7020 | Object could not be updated | SET | The requested object could not be updated. |
| 7021 | Required parameter failed | ADD, SET | A required parameter failed to update. |
| 7022 | Command failure | OPERATE | An operation failed to complete. |
| 7023 | Command canceled | OPERATE | An asynchronous operation was canceled. |
| 7024 | Delete failure | DELETE | Object deletion failed. |
| 7025 | Duplicate key | ADD | An object with the requested unique keys already exists. |
| 7026 | Invalid path | Any | The supplied path does not match the supported data model. |
| 7027 | Invalid command arguments | OPERATE | Operation arguments were invalid or unknown. |
| 7100–7199 | USP Record errors | — | Message Transfer Protocol errors. |
| 7800–7999 | Vendor-defined | — | Vendor-defined USP errors. |

See the Broadband Forum USP specification for the authoritative protocol definition.

---

# 🔌 Language Interoperability

The primary public interface is the C ABI.

This makes the library suitable for integration with languages that provide C FFI support.

Potential integrations include:

| Language | Integration | Status |
|---|---|:---:|
| C | Native C ABI | ✅ |
| C++ | Native C ABI | ✅ |
| Rust | C FFI | ✅ |
| Python | CFFI / ctypes / extension | 🚧 |
| Go | cgo | 🚧 |
| Java | JNI / Panama | 🚧 |

Language-specific bindings should remain thin wrappers around the stable C ABI.

---

# 🛡️ API & ABI Stability

The public C API is designed to be stable across library releases.

The project avoids exposing C++ ABI details publicly.

In particular, consumers should not need to know about:

- C++ classes
- STL containers
- Allocators
- Exceptions
- Templates
- C++ object layouts
- Internal thread implementations
- Coroutine implementations

This allows the internal implementation to evolve without unnecessarily breaking downstream applications.

---

# 📋 Standards

All implementation work must follow the project's engineering standards.

See:

**[`AGENTS.md`](AGENTS.md)**

The document defines requirements for:

- C++20 usage
- C ABI design
- Memory safety
- Ownership
- RAII
- Thread management
- Coroutines
- Error handling
- ABI stability
- API evolution
- Testing
- Sanitizers
- Build systems
- Code review
- Automated coding agents

---

# 🤝 Contributing

Contributions are welcome.

Before submitting a change:

1. Read [`AGENTS.md`](AGENTS.md).
2. Build the project.
3. Run the test suite.
4. Run relevant sanitizer configurations.
5. Add tests for new behavior.
6. Update public API documentation when necessary.
7. Verify that C ABI compatibility has not been unintentionally changed.

Please keep pull requests focused and avoid mixing unrelated refactoring with functional changes.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution workflow.

To report a security vulnerability, follow [`SECURITY.md`](SECURITY.md) —
do not open a public issue.

---

# 🗺️ Roadmap

### Current

- [x] C-compatible public API
- [x] C++20 implementation
- [x] USP GET
- [x] USP SET
- [x] USP OPERATE
- [x] USP subscriptions
- [x] UDS transport
- [x] Static library
- [x] Shared library
- [x] C, C++ and Rust examples (verified live via `test/compose.yml`)
- [x] ASan + UBSan CI
- [x] Compose test workflow (examples build and hold live USP sessions per PR)

### Next

- [ ] REGISTER
- [ ] ADD
- [ ] DELETE
- [ ] GET_SUPPORTED_DM
- [ ] GET_INSTANCES
- [ ] GET_SUPPORTED_PROTOCOL
- [ ] Expanded transport support
- [ ] TSan CI
- [ ] API/ABI compatibility CI
- [ ] Package-manager support
- [ ] API documentation site

---

# ⭐ Project Status

> **Early development**

The core controller functionality is operational, but the API and implementation are still evolving.

The stable C ABI is intended to provide a durable integration point while the internal implementation continues to mature.

Production users should pin a known library version and review the release notes before upgrading.

---

# 📜 License

**Apache-2.0**

All project source files carry an `SPDX-License-Identifier: Apache-2.0` header.
The only exceptions are generated files (e.g. `Cargo.lock`), VCS metadata
(e.g. `.gitignore`), and the vendored upstream inputs under `proto/` and
`specification/`, which are never modified.

---

# 🙏 Acknowledgements

This project implements functionality based on the **Broadband Forum USP (TR-369)** specifications.

Thanks to the open-source broadband and embedded networking communities for their work on USP implementations and tooling.

---

<div align="center">

## Built for systems that need to talk USP.

**C++20 · C ABI · USP / TR-369**

<br />

[![GitHub stars](https://img.shields.io/github/stars/kartikg33/libuspmtp?style=for-the-badge&logo=github)](#)
[![GitHub forks](https://img.shields.io/github/forks/kartikg33/libuspmtp?style=for-the-badge&logo=github)](#)
[![GitHub issues](https://img.shields.io/github/issues/kartikg33/libuspmtp?style=for-the-badge&logo=github)](#)
[![GitHub license](https://img.shields.io/github/license/kartikg33/libuspmtp?style=for-the-badge)](#)

<br />

**[Documentation](#) · [Examples](#) · [Discussions](#) · [Issues](#)**

</div>
