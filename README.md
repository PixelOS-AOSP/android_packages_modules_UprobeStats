# UprobeStats

UprobeStats provides dynamic instrumentation on Android using uprobes and eBPF
(extended Berkeley Packet Filter). It allows for server-configurable probing of
userspace processes (like `system_server`) to observe function invocations.
Importantly, it enables adding and modifying *instrumentation* without modifying
the *binary* in question (e.g. shipping modified source code).

## Project Structure

### `apex/`

Contains the build configuration for the `com.android.uprobestats` APEX module.

### `bpf/`

Contains C++ headers and libraries for BPF interaction, including syscall
wrappers and shared struct definitions.

### `bpf_progs/`

Contains the C source files for the BPF programs that are attached via kernel
uprobes.

### `bpfloader/`

Contains `uprobestatsbpfload`, a custom BPF loader binary responsible for
loading the BPF programs packaged within the module into the kernel (required
since APEXes must ship with their own loader).

### `config/`

Defines the configuration format for UprobeStats, including the `config.proto`
definition for tasks, probes, and targets.

### `daemon/`

The core userspace daemon. **This directory contains the majority of the logic
for the module**, orchestrating the instrumentation sessions.

*   `uprobestats.rs`: The main entry point.
*   `android/`: Android-specific implementations, including Binder service
    registration, BPF map polling logic, and atom writing.
*   `core/`: Platform-independent logic for configuration resolution, BPF map
    abstraction, and task management.
*   `ffi/`: Foreign Function Interfaces (FFI) to interact with C/C++ libraries
    (ActivityManager, BPF syscalls, StatsD).
*   `aidl/`: AIDL definition for `IUprobeStatsService`, the interface used to
    control the daemon.

### `flags/`

Contains Aconfig flag definitions (`*.aconfig`) to gate features and
instrumentation logic.

### `framework/`

Contains the Java APIs exposed by the module to the Android Framework, intended
for a privileged, privacy-preserving app to receive signals.

### `lib/`

C++ client library for interacting with the UprobeStats daemon. `statsd` is the
component that actually starts UprobeStats by delivering a config.

### `service/`

The Java system service, `UprobeStatsBridgeService`, which runs inside
`system_server`.

*   Acts as a bridge between the native UprobeStats daemon and the Android
    framework.
*   Exposes Java SDK functionality to the native daemon via the
    `IUprobeStatsBridgeService` AIDL, as the native daemon cannot access these
    APIs directly.
*   Acts as a conduit for the daemon to send data to the privileged,
    privacy-preserving app called out in `framework/`.

### `test/`

Comprehensive testing infrastructure.

*   `cts/`: Compatibility Test Suite (CTS) tests ensuring public APIs behave
    correctly.
*   `res/`: Test configurations in `.textproto` format.
*   `src/`: Host-side tests (`UprobeStatsTest.java`, `ArtTest.java`) that push
    configs and verify StatsD atoms.
*   `*TestApp/`: Helper Android apps used as targets for instrumentation during
    tests.

## How it Works

1.  **Configuration**: A `UprobestatsConfig` is pushed to the device via statsd
    `Subscription`s.
2.  **Resolution**: The Daemon (`daemon/`) resolves the target methods to
    specific offsets in the ELF binaries on the device.
3.  **Attachment**: The Daemon loads the BPF programs (`bpf_progs/`) and
    attaches them to the resolved offsets using the kernel's `perf_event_open`
    API.
4.  **Collection**:
    *   **BPF Maps**: The BPF programs write data (timestamps, arguments) into
        BPF ring buffers.
    *   **Polling**: The Daemon polls these maps
        (`daemon/android/bpf_handler.rs`).
5.  **Reporting**:
    *   **StatsD**: Data is processed and written as atoms to StatsD
        (`daemon/android/atom.rs`).
    *   **Bridge Service**: Complex events or those requiring framework context
        are sent to the `UprobeStatsBridgeService` (`service/`), which can then
        forward them to the privileged app for anti-abuse purposes.
