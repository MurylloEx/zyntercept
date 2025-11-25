# Zyntercept

Zyntercept is a Zydis-based library that provides function hooking capabilities for x86 and x86_64 microprocessor architectures. The library enables the creation of security software and instrumentation of Win32/Linux APIs with support for `__fastcall`, `__stdcall`, and `__cdecl` calling conventions.

## Table of Contents

- [About the Project](#about-the-project)
- [Purpose](#purpose)
- [Installation and Build](#installation-and-build)
  - [Linux](#linux)
  - [Windows](#windows)
- [Minimal Examples](#minimal-examples)
  - [Linux Example: Hooking the `read` syscall](#linux-example-hooking-the-read-syscall)
  - [Windows Example: Hooking the `ReadFile` function](#windows-example-hooking-the-readfile-function)
- [High-Level API](#high-level-api)
- [Core Concepts](#core-concepts)
- [Requirements](#requirements)
- [Features](#features)
- [Limitations and Considerations](#limitations-and-considerations)
- [License](#license)

## About the Project

Zyntercept implements a transaction-based hooking system that allows developers to intercept function calls in a safe and atomic manner. The library automatically handles the complexity of instruction analysis, trampoline generation, and memory management, providing a clean and straightforward interface for function interception.

The library is designed to work with both 32-bit and 64-bit processes on Windows and Unix-based operating systems, making it suitable for cross-platform development scenarios.

### Architecture

<img src="./architecture.svg" alt="Zyntercept Architecture" />
<p align="center"><em>Figure 1: Zyntercept engine architecture and interaction flow</em></p>

### Key Features

- **Transaction-based hooking system**: All hook operations are executed within a transaction, ensuring atomicity
- **Cross-platform support**: Works on Windows and Unix systems (Linux, etc.)
- **Supported architectures**: x86 (32-bit) and x86_64 (64-bit)
- **Automatic trampoline generation**: Preserves the original behavior of functions
- **Intelligent instruction analysis**: Automatically relocates complex instructions
- **Thread-safe**: Safe transaction management in multithreaded environments

## Purpose

Zyntercept was created to provide a robust and cross-platform solution for system-level function interception. The main use cases include:

1. **Security Software**: Detection and prevention of malicious behavior through interception of system calls
2. **API Instrumentation**: Monitoring and logging of operating system function calls
3. **Malware Analysis**: Interception of syscalls for behavioral analysis
4. **Debug Tool Development**: Function interception for execution flow analysis
5. **Application Patching**: Modification of application behavior without changing source code

The library uses the Zydis library for instruction disassembly, enabling precise analysis and safe code relocation during the hooking process.

## Installation and Build

### Linux

<details>
<summary><b>Click to expand</b></summary>

#### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake git

# Fedora/RHEL
sudo dnf install gcc gcc-c++ cmake git
```

#### Build

```bash
# Clone the repository (if you haven't already)
git clone <repository-url>
cd zyntercept

# Generate build files
cmkr gen

# Or use CMake directly
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release

# Compile
cmake --build build --config Release

# The library will be generated in:
# build/libZyntercept.a (static)
# build/libZyntercept.so (dynamic, if configured)
```

#### Build for 32-bit (on 64-bit system)

```bash
# Install 32-bit development dependencies
sudo apt-get install gcc-multilib g++-multilib

# Configure for 32-bit
cmake -S . -B build32 \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_C_FLAGS="-m32" \
    -D CMAKE_CXX_FLAGS="-m32"

cmake --build build32
```

#### Installation (Optional)

```bash
# Install to system
sudo cmake --install build --prefix /usr/local

# Or to a specific directory
cmake --install build --prefix ~/zyntercept-install
```

</details>

### Windows

<details>
<summary><b>Click to expand</b></summary>

#### Prerequisites

- Visual Studio 2017 or later (with C++ Desktop Development)
- CMake 3.15 or higher
- Git for Windows (optional)

#### Build with Visual Studio

```powershell
# Generate build files
cmkr gen

# Or use CMake directly for x64
cmake -G "Visual Studio 17 2022" -A x64 -S . -B build64 -D CMAKE_BUILD_TYPE=Release
cmake --build build64 --config Release

# For x86 (32-bit)
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B build32 -D CMAKE_BUILD_TYPE=Release
cmake --build build32 --config Release
```

#### Build via Command Line

```powershell
# Debug x64
cmake -G "Visual Studio 17 2022" -A x64 -S . -B build64 -D CMAKE_BUILD_TYPE=Debug
cmake --build build64 --config Debug

# Release x64
cmake -G "Visual Studio 17 2022" -A x64 -S . -B build64 -D CMAKE_BUILD_TYPE=Release
cmake --build build64 --config Release

# Debug x86
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B build32 -D CMAKE_BUILD_TYPE=Debug
cmake --build build32 --config Debug

# Release x86
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B build32 -D CMAKE_BUILD_TYPE=Release
cmake --build build32 --config Release
```

#### Generated Files Location

```
build64/
  ├── Debug/
  │   ├── Zyntercept.lib
  │   └── Zyntercept.pdb
  └── Release/
      └── Zyntercept.lib

build32/
  ├── Debug/
  │   ├── Zyntercept.lib
  │   └── Zyntercept.pdb
  └── Release/
      └── Zyntercept.lib
```

#### Using in Visual Studio

1. Open the `zyntercept.sln` file generated in the build directory
2. Select the configuration (Debug/Release) and platform (x86/x64)
3. Build the `Zyntercept` project

</details>

## Minimal Examples

### Linux Example: Hooking the `read` syscall

<details>
<summary><b>Click to expand</b></summary>

This example demonstrates how to intercept the `read` syscall on Linux:

```cpp
#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>

// Original function declaration
ssize_t read(int fd, void* buf, size_t count);

// Interception function
static ssize_t InterceptRead(int fd, void* buf, size_t count) {
    printf("[HOOK] read() called: fd=%d, count=%zu\n", fd, count);

    // Call the original function through the trampoline
    ssize_t result = OriginalRead(fd, buf, count);

    printf("[HOOK] read() returned: %zd bytes\n", result);

    return result;
}

// Declare the trampoline
TRAMPOLINE(read);

int main() {
    // Configure the process
    ZynterceptProcess Process = { 0 };
    Process.Identifier = (void*)(uintptr_t)getpid();
    Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    // Apply the hook
    if (!ZynterceptTransactionBegin()) {
        fprintf(stderr, "Error starting transaction\n");
        return 1;
    }

    if (!ZynterceptAttachProcess(&Process)) {
        fprintf(stderr, "Error attaching process\n");
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptAttach(ROUTINE(read), INTERCEPTION(read))) {
        fprintf(stderr, "Error attaching hook\n");
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptTransactionCommit()) {
        fprintf(stderr, "Error committing transaction\n");
        return 1;
    }

    // Test the hook
    char buffer[256];
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Content read: %s\n", buffer);
        }
        close(fd);
    }

    // Remove the hook
    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptDetach(ROUTINE(read));
    ZynterceptTransactionCommit();

    return 0;
}
```

**Compilation:**

```bash
g++ -o example_read example_read.cpp -L./build -lZyntercept -I./Zyntercept
```

</details>

### Windows Example: Hooking the `ReadFile` function

<details>
<summary><b>Click to expand</b></summary>

This example demonstrates how to intercept the `ReadFile` function on Windows (equivalent to Linux's `read`):

```cpp
#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <Windows.h>
#include <cstdio>

// Original function declaration
BOOL ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

// Interception function
static BOOL InterceptReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped)
{
    printf("[HOOK] ReadFile() called: handle=0x%p, bytes=%lu\n",
           hFile, nNumberOfBytesToRead);

    // Call the original function through the trampoline
    BOOL result = OriginalReadFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped
    );

    if (result && lpNumberOfBytesRead) {
        printf("[HOOK] ReadFile() returned: %lu bytes read\n",
               *lpNumberOfBytesRead);
    }

    return result;
}

// Declare the trampoline
TRAMPOLINE(ReadFile);

int main() {
    // Configure the process
    ZynterceptProcess Process = { 0 };
    Process.Identifier = GetCurrentProcess();
    Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    // Apply the hook
    if (!ZynterceptTransactionBegin()) {
        fprintf(stderr, "Error starting transaction\n");
        return 1;
    }

    if (!ZynterceptAttachProcess(&Process)) {
        fprintf(stderr, "Error attaching process\n");
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptAttach(ROUTINE(ReadFile), INTERCEPTION(ReadFile))) {
        fprintf(stderr, "Error attaching hook\n");
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptTransactionCommit()) {
        fprintf(stderr, "Error committing transaction\n");
        return 1;
    }

    // Test the hook
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[256] = { 0 };
        DWORD bytesRead = 0;

        if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            printf("Content read: %s\n", buffer);
        }

        CloseHandle(hFile);
    }

    // Remove the hook
    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptDetach(ROUTINE(ReadFile));
    ZynterceptTransactionCommit();

    return 0;
}
```

**Compilation (Visual Studio):**

Add the project to your solution or compile via command line:

```powershell
cl /EHsc example_readfile.cpp /I. /link Zyntercept.lib
```

</details>

## High-Level API

<details>
<summary><b>ZynterceptTransactionBegin</b></summary>

```cpp
bool ZynterceptTransactionBegin();
```

Initiates a new transaction. Only one transaction can be active at a time.

**Returns**: `true` if the transaction was successfully initiated, `false` if a transaction is already open.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Example:**

```cpp
if (!ZynterceptTransactionBegin()) {
    // Handle error: transaction may already be open
    return false;
}
```

</details>

<details>
<summary><b>ZynterceptTransactionCommit</b></summary>

```cpp
bool ZynterceptTransactionCommit();
```

Commits all pending hook operations in the current transaction. If any hook fails to apply, all hooks are automatically rolled back and the function returns `false`.

**Returns**: `true` if all hooks were successfully applied, `false` if any hook failed (automatic rollback performed).

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Example:**

```cpp
if (!ZynterceptTransactionCommit()) {
    // Automatic rollback occurred
    return false;
}
```

</details>

<details>
<summary><b>ZynterceptTransactionAbandon</b></summary>

```cpp
bool ZynterceptTransactionAbandon();
```

Abandons the current transaction without applying any changes. All queued operations are discarded.

**Returns**: `true` if the transaction was successfully abandoned, `false` if no transaction is currently open.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Example:**

```cpp
if (!ZynterceptAttach(ROUTINE(Function), INTERCEPTION(Function))) {
    ZynterceptTransactionAbandon();
    return false;
}
```

</details>

<details>
<summary><b>ZynterceptAttachProcess</b></summary>

```cpp
bool ZynterceptAttachProcess(ZynterceptProcess* Process);
```

Specifies the target process for hooking operations within the current transaction. Must be called after `ZynterceptTransactionBegin()` and before `ZynterceptAttach()` or `ZynterceptDetach()`.

**Parameters:**

- `Process`: Pointer to a `ZynterceptProcess` structure containing the process identifier and architecture.

**Returns**: `true` if the process was successfully attached, `false` if the transaction is not open or the process identifier is invalid.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**ZynterceptProcess Structure:**

```cpp
typedef struct ZynterceptProcess_ {
    ZynterceptHandle Identifier;  // HANDLE (Windows) or pid_t (Unix)
    ZynterceptArchitecture Architecture;  // ZYNTERCEPT_ARCHITECTURE_32BIT or 64BIT
} ZynterceptProcess;
```

**Example:**

```cpp
ZynterceptProcess Process = { 0 };

#if defined(ZYNTERCEPT_WINDOWS)
Process.Identifier = GetCurrentProcess();
#elif defined(ZYNTERCEPT_UNIX)
Process.Identifier = (void*)(uintptr_t)getpid();
#endif

Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
    ? ZYNTERCEPT_ARCHITECTURE_64BIT
    : ZYNTERCEPT_ARCHITECTURE_32BIT;

if (!ZynterceptAttachProcess(&Process)) {
    ZynterceptTransactionAbandon();
    return false;
}
```

</details>

<details>
<summary><b>ZynterceptAttach</b></summary>

```cpp
bool ZynterceptAttach(void** TargetRoutine, void* InterceptionRoutine);
```

Queues a function hook for attachment. The hook will be applied when `ZynterceptTransactionCommit()` is called.

**Parameters:**

- `TargetRoutine`: Pointer to a function pointer that will be redirected to the trampoline after hooking.
- `InterceptionRoutine`: Pointer to the interception function that will be called instead of the original function.

**Returns**: `true` if the hook was successfully queued, `false` if the transaction is not open or parameters are invalid.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Note**: Use the `ROUTINE()` and `INTERCEPTION()` macros for convenience when working with C++ code.

**Example:**

```cpp
if (!ZynterceptAttach(ROUTINE(ReadFile), INTERCEPTION(ReadFile))) {
    ZynterceptTransactionAbandon();
    return false;
}
```

</details>

<details>
<summary><b>ZynterceptDetach</b></summary>

```cpp
bool ZynterceptDetach(void** TargetRoutine);
```

Queues a function hook for removal. The hook will be removed when `ZynterceptTransactionCommit()` is called.

**Parameters:**

- `TargetRoutine`: Pointer to the function pointer that was used when attaching the hook.

**Returns**: `true` if the hook was successfully queued for removal, `false` if the transaction is not open or the hook is not currently attached.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Note**: Use the `ROUTINE()` macro for convenience when working with C++ code.

**Example:**

```cpp
ZynterceptTransactionBegin();
ZynterceptAttachProcess(&Process);
ZynterceptDetach(ROUTINE(ReadFile));
ZynterceptTransactionCommit();
```

</details>

<details>
<summary><b>Helper Macros</b></summary>

#### TRAMPOLINE

```cpp
TRAMPOLINE(Routine);
```

Declares a trampoline pointer for the specified function. Creates a pointer named `Original##Routine` that points to the trampoline after hooking.

**Parameters:**

- `Routine`: Name of the function (without parentheses or parameters).

**Example:**

```cpp
TRAMPOLINE(ReadFile);
// Creates: static decltype(&ReadFile) OriginalReadFile = &ReadFile;
```

#### ROUTINE

```cpp
ROUTINE(Routine);
```

Returns the address of the function pointer for use with `ZynterceptAttach()` or `ZynterceptDetach()`.

**Parameters:**

- `Routine`: Name of the function (without parentheses or parameters).

**Returns**: Address of the function pointer (`void**`).

**Example:**

```cpp
ZynterceptAttach(ROUTINE(ReadFile), INTERCEPTION(ReadFile));
```

#### INTERCEPTION

```cpp
INTERCEPTION(Routine);
```

Returns the address of the interception function for use with `ZynterceptAttach()`.

**Parameters:**

- `Routine`: Name of the interception function (without parentheses or parameters).

**Returns**: Address of the interception function (`void*`).

**Example:**

```cpp
ZynterceptAttach(ROUTINE(ReadFile), INTERCEPTION(ReadFile));
```

</details>

## Core Concepts

<details>
<summary><b>Transactions</b></summary>

Zyntercept uses a transaction-based model for hook management. All hook operations must be performed within a transaction context. This design ensures atomicity: either all hooks in a transaction are successfully applied, or none are applied at all.

**Transaction Flow:**

1. `ZynterceptTransactionBegin()` - Starts the transaction
2. `ZynterceptAttachProcess()` - Specifies the target process
3. `ZynterceptAttach()` / `ZynterceptDetach()` - Queues operations
4. `ZynterceptTransactionCommit()` - Applies all operations atomically

If any operation fails during commit, all changes are automatically reverted.

</details>

<details>
<summary><b>Process Attachment</b></summary>

Before attaching hooks, you must specify the target process. The library supports hooking functions in the current process or external processes (subject to platform-specific permissions).

**Current Process:**

```cpp
#if defined(ZYNTERCEPT_WINDOWS)
Process.Identifier = GetCurrentProcess();
#elif defined(ZYNTERCEPT_UNIX)
Process.Identifier = (void*)(uintptr_t)getpid();
#endif
```

**External Process (requires appropriate permissions):**

```cpp
#if defined(ZYNTERCEPT_WINDOWS)
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
Process.Identifier = hProcess;
#elif defined(ZYNTERCEPT_UNIX)
Process.Identifier = (void*)(uintptr_t)targetPid;
#endif
```

</details>

<details>
<summary><b>Trampolines</b></summary>

When a function is hooked, Zyntercept automatically generates a trampoline that preserves the original function's behavior. The trampoline contains the original instructions from the function's prologue, relocated to a safe memory location, followed by a jump back to the continuation point in the original function.

**How It Works:**

1. Zyntercept analyzes the first instructions of the target function
2. Relocates these instructions to an allocated memory area nearby
3. Adds a jump back to continue execution after the prologue
4. Replaces the original prologue with a jump to the interception function
5. The trampoline pointer points to the relocated code

This allows the interception function to call the original function through the trampoline without causing infinite recursion.

</details>

## Requirements

- **CMake**: 3.15 or higher
- **C++ Compiler**: With C++11 support
- **Zydis**: 4.0.0 (automatically fetched via CMake)
- **Windows**: Visual Studio 2017 or later (for Windows builds)
- **Unix/Linux**: GCC or Clang with standard development tools

### Automatic Dependencies

Zydis is automatically fetched by CMake during project configuration, so there's no need to install it manually.

## Features

<details>
<summary><b>Click to expand</b></summary>

- Transaction-based hooking system with atomic commit and rollback capabilities
- Support for x86 and x86_64 architectures
- Cross-platform support for Windows and Unix-based systems
- Automatic trampoline generation for calling original functions
- Intelligent instruction analysis and relocation
- Support for functions with complex prologues, including loops and conditional branches
- Thread-safe transaction management
- Automatic rollback on failure

</details>

## Limitations and Considerations

<details>
<summary><b>Function Prologue Requirements</b></summary>

Functions must have a prologue of sufficient size to accommodate the detour jump instruction (5 bytes for x86, 14 bytes for x64). Functions with very short prologues may not be hookable.

</details>

<details>
<summary><b>Instruction Relocation</b></summary>

The library automatically relocates instructions from the function prologue to the trampoline. Complex instructions, particularly those with relative addressing, are handled automatically. However, certain edge cases may not be supported.

</details>

<details>
<summary><b>Thread Safety</b></summary>

While the transaction API is thread-safe, care must be taken when hooking functions that may be called from multiple threads. The interception functions themselves are not automatically synchronized.

</details>

<details>
<summary><b>Process Permissions</b></summary>

Hooking functions in external processes requires appropriate permissions. On Windows, this typically requires administrator privileges or debug privileges. On Unix systems, appropriate permissions depend on the target process ownership and system configuration.

</details>

<details>
<summary><b>Memory Allocation</b></summary>

The library allocates memory for trampolines near the target function to ensure that relative jumps remain within range. If memory allocation fails, hooking will fail.

</details>

<details>
<summary><b>Recursive Functions</b></summary>

The library supports hooking recursive functions. When calling the original function through the trampoline from within an interception function, the interception will not be triggered again for that call.

</details>

## License

<details>
<summary><b>Click to expand</b></summary>

Copyright (c) 2024 Muryllo Pimenta

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

</details>
