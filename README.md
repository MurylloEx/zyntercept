# Zyntercept

Zyntercept is a Zydis-based library that provides function hooking capabilities for x86 and x86_64 microprocessor architectures. The library enables the creation of security software and instrumentation of Win32/Linux APIs with support for `__fastcall`, `__stdcall`, and `__cdecl` calling conventions.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Building](#building)
- [Core Concepts](#core-concepts)
- [High-Level API](#high-level-api)
- [Usage Guide](#usage-guide)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)
- [Limitations and Considerations](#limitations-and-considerations)
- [License](#license)

## Overview

Zyntercept implements a transaction-based hooking system that allows developers to intercept function calls in a safe and atomic manner. The library automatically handles the complexity of instruction analysis, trampoline generation, and memory management, providing a clean and straightforward interface for function interception.

The library is designed to work with both 32-bit and 64-bit processes on Windows and Unix-based operating systems, making it suitable for cross-platform development scenarios.

## Features

- Transaction-based hooking system with atomic commit and rollback capabilities
- Support for x86 and x86_64 architectures
- Cross-platform support for Windows and Unix-based systems
- Automatic trampoline generation for calling original functions
- Intelligent instruction analysis and relocation
- Support for functions with complex prologues, including loops and conditional branches
- Thread-safe transaction management
- Automatic rollback on failure

## Requirements

- CMake 3.15 or higher
- C++ compiler with C++11 support
- Zydis 4.0.0 (automatically fetched via CMake)
- Windows: Visual Studio 2017 or later (for Windows builds)
- Unix: GCC or Clang with standard development tools

## Building

### Generating Build Files

```sh
cd zyntercept
cmkr gen
```

### Windows Build (Visual Studio)

#### Debug Configuration

```sh
# For x86 (32-bit)
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B "build32" -D CMAKE_BUILD_TYPE=Debug
cmake --build build32/

# For x64 (64-bit)
cmake -G "Visual Studio 17 2022" -A x64 -S . -B "build64" -D CMAKE_BUILD_TYPE=Debug
cmake --build build64/
```

#### Release Configuration

```sh
# For x86 (32-bit)
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B "build32" -D CMAKE_BUILD_TYPE=Release
cmake --build build32/

# For x64 (64-bit)
cmake -G "Visual Studio 17 2022" -A x64 -S . -B "build64" -D CMAKE_BUILD_TYPE=Release
cmake --build build64/
```

## Core Concepts

### Transactions

Zyntercept uses a transaction-based model for hook management. All hook operations must be performed within a transaction context. This design ensures atomicity: either all hooks in a transaction are successfully applied, or none are applied at all.

### Process Attachment

Before attaching hooks, you must specify the target process. The library supports hooking functions in the current process or external processes (subject to platform-specific permissions).

### Trampolines

When a function is hooked, Zyntercept automatically generates a trampoline that preserves the original function's behavior. The trampoline contains the original instructions from the function's prologue, relocated to a safe memory location, followed by a jump back to the continuation point in the original function.

### Macros

The library provides convenience macros for C++ code:

- `TRAMPOLINE(Routine)`: Declares a trampoline pointer for the original function
- `ROUTINE(Routine)`: Returns the address of the function pointer (for use with `ZynterceptAttach`)
- `INTERCEPTION(Routine)`: Returns the address of the interception function

## High-Level API

The high-level API consists of the following functions:

- `ZynterceptTransactionBegin()`: Initiates a new transaction
- `ZynterceptTransactionCommit()`: Commits all pending hook operations
- `ZynterceptTransactionAbandon()`: Abandons the current transaction without applying changes
- `ZynterceptAttachProcess()`: Specifies the target process for hooking operations
- `ZynterceptAttach()`: Queues a function hook for attachment
- `ZynterceptDetach()`: Queues a function hook for removal

## Usage Guide

### Basic Workflow

The standard workflow for hooking a function consists of the following steps:

1. Define the original function and the interception function
2. Declare a trampoline using the `TRAMPOLINE` macro
3. Configure the target process information
4. Begin a transaction
5. Attach the process
6. Attach the hook
7. Commit the transaction

### Step-by-Step Instructions

#### Step 1: Define Functions

Define the function you wish to intercept and create an interception function with matching signature:

```cpp
// Original function
static float CalculateSum(float a, float b) {
    return a + b;
}

// Interception function
static float InterceptCalculateSum(float a, float b) {
    // Custom logic here
    // Call original function via trampoline
    return OriginalCalculateSum(a, b);
}
```

#### Step 2: Declare Trampoline

Use the `TRAMPOLINE` macro to declare the trampoline pointer:

```cpp
TRAMPOLINE(CalculateSum);
```

This macro creates a pointer named `OriginalCalculateSum` that will point to the trampoline after the hook is applied.

#### Step 3: Configure Process

Initialize a `ZynterceptProcess` structure with the target process information:

```cpp
ZynterceptProcess Process = { 0 };

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
Process.Identifier = GetCurrentProcess();
#elif defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
Process.Identifier = (void*)getpid();
#endif

Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
    ? ZYNTERCEPT_ARCHITECTURE_64BIT
    : ZYNTERCEPT_ARCHITECTURE_32BIT;
```

#### Step 4: Begin Transaction

Start a new transaction:

```cpp
if (!ZynterceptTransactionBegin()) {
    // Handle error: transaction may already be open
    return false;
}
```

#### Step 5: Attach Process

Specify the target process for the transaction:

```cpp
if (!ZynterceptAttachProcess(&Process)) {
    // Handle error: invalid process or transaction not open
    ZynterceptTransactionAbandon();
    return false;
}
```

#### Step 6: Attach Hook

Queue the function hook for attachment:

```cpp
if (!ZynterceptAttach(ROUTINE(CalculateSum), INTERCEPTION(CalculateSum))) {
    // Handle error: transaction not open or invalid parameters
    ZynterceptTransactionAbandon();
    return false;
}
```

#### Step 7: Commit Transaction

Apply all queued hooks atomically:

```cpp
if (!ZynterceptTransactionCommit()) {
    // Handle error: hook application failed, automatic rollback performed
    return false;
}
```

### Removing Hooks

To remove a hook, follow the same workflow but use `ZynterceptDetach` instead of `ZynterceptAttach`:

```cpp
ZynterceptTransactionBegin();
ZynterceptAttachProcess(&Process);
ZynterceptDetach(ROUTINE(CalculateSum));
ZynterceptTransactionCommit();
```

### Multiple Hooks in a Single Transaction

You can attach or remove multiple hooks within a single transaction:

```cpp
ZynterceptTransactionBegin();
ZynterceptAttachProcess(&Process);

ZynterceptAttach(ROUTINE(Function1), INTERCEPTION(Function1));
ZynterceptAttach(ROUTINE(Function2), INTERCEPTION(Function2));
ZynterceptAttach(ROUTINE(Function3), INTERCEPTION(Function3));

ZynterceptTransactionCommit(); // All hooks applied atomically
```

## Examples

### Example 1: Basic Function Interception

This example demonstrates intercepting a simple arithmetic function:

```cpp
#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
#endif

// Original function
static int Multiply(int a, int b) {
    return a * b;
}

// Interception function
static int InterceptMultiply(int a, int b) {
    // Log the call or modify behavior
    int result = OriginalMultiply(a, b);
    return result * 2; // Modify return value
}

TRAMPOLINE(Multiply);

int main() {
    // Configure process
    ZynterceptProcess Process = { 0 };

#if defined(ZYNTERCEPT_WINDOWS)
    Process.Identifier = GetCurrentProcess();
#elif defined(ZYNTERCEPT_UNIX)
    Process.Identifier = (void*)getpid();
#endif

    Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    // Apply hook
    if (!ZynterceptTransactionBegin()) {
        return 1;
    }

    if (!ZynterceptAttachProcess(&Process)) {
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptAttach(ROUTINE(Multiply), INTERCEPTION(Multiply))) {
        ZynterceptTransactionAbandon();
        return 1;
    }

    if (!ZynterceptTransactionCommit()) {
        return 1;
    }

    // Function is now hooked
    int result = Multiply(5, 3); // Returns 30 (15 * 2)

    // Remove hook
    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptDetach(ROUTINE(Multiply));
    ZynterceptTransactionCommit();

    // Function behavior restored
    result = Multiply(5, 3); // Returns 15

    return 0;
}
```

### Example 2: Conditional Interception

This example demonstrates conditional behavior in an interception function:

```cpp
static int ProcessValue(int value) {
    if (value < 0) {
        return 0;
    }
    return value * 2;
}

static int InterceptProcessValue(int value) {
    // Only intercept positive values
    if (value > 100) {
        return -1; // Reject large values
    }
    return OriginalProcessValue(value);
}

TRAMPOLINE(ProcessValue);
```

### Example 3: Multiple Hooks with Error Handling

This example demonstrates proper error handling when applying multiple hooks:

```cpp
bool ApplyHooks() {
    ZynterceptProcess Process = { 0 };

    // ... configure process ...

    if (!ZynterceptTransactionBegin()) {
        return false;
    }

    if (!ZynterceptAttachProcess(&Process)) {
        ZynterceptTransactionAbandon();
        return false;
    }

    // Queue multiple hooks
    if (!ZynterceptAttach(ROUTINE(Function1), INTERCEPTION(Function1)) ||
        !ZynterceptAttach(ROUTINE(Function2), INTERCEPTION(Function2)) ||
        !ZynterceptAttach(ROUTINE(Function3), INTERCEPTION(Function3))) {
        ZynterceptTransactionAbandon();
        return false;
    }

    // Commit: all hooks applied atomically, or none if any fails
    if (!ZynterceptTransactionCommit()) {
        // Automatic rollback occurred
        return false;
    }

    return true;
}
```

## Error Handling

All API functions return boolean values indicating success or failure. It is essential to check return values and handle errors appropriately.

### Common Error Scenarios

1. **Transaction Already Open**: `ZynterceptTransactionBegin()` returns `false` if a transaction is already active. Always check the return value and abandon the previous transaction if necessary.

2. **Transaction Not Open**: `ZynterceptAttach()`, `ZynterceptDetach()`, and `ZynterceptAttachProcess()` return `false` if called outside a transaction context.

3. **Invalid Process**: `ZynterceptAttachProcess()` returns `false` if the process identifier is invalid or null.

4. **Hook Application Failure**: `ZynterceptTransactionCommit()` returns `false` if any hook in the transaction fails to apply. The library automatically performs rollback in this case.

5. **Detach Failure**: `ZynterceptDetach()` returns `false` if the specified hook is not currently attached.

### Error Handling Best Practices

Always check return values and use `ZynterceptTransactionAbandon()` to clean up failed transactions:

```cpp
if (!ZynterceptTransactionBegin()) {
    // Handle: transaction may already be open
    if (ZynterceptTransactionAbandon()) {
        // Retry
        if (!ZynterceptTransactionBegin()) {
            return false;
        }
    } else {
        return false;
    }
}

if (!ZynterceptAttachProcess(&Process)) {
    ZynterceptTransactionAbandon();
    return false;
}

if (!ZynterceptAttach(ROUTINE(Function), INTERCEPTION(Function))) {
    ZynterceptTransactionAbandon();
    return false;
}

if (!ZynterceptTransactionCommit()) {
    // Automatic rollback occurred, no need to abandon
    return false;
}
```

## API Reference

### ZynterceptTransactionBegin

```cpp
bool ZynterceptTransactionBegin();
```

Initiates a new transaction. Only one transaction can be active at a time.

**Returns**: `true` if the transaction was successfully initiated, `false` if a transaction is already open.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

### ZynterceptTransactionCommit

```cpp
bool ZynterceptTransactionCommit();
```

Commits all pending hook operations in the current transaction. If any hook fails to apply, all hooks are automatically rolled back and the function returns `false`.

**Returns**: `true` if all hooks were successfully applied, `false` if any hook failed (automatic rollback performed).

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

### ZynterceptTransactionAbandon

```cpp
bool ZynterceptTransactionAbandon();
```

Abandons the current transaction without applying any changes. All queued operations are discarded.

**Returns**: `true` if the transaction was successfully abandoned, `false` if no transaction is currently open.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

### ZynterceptAttachProcess

```cpp
bool ZynterceptAttachProcess(ZynterceptProcess* Process);
```

Specifies the target process for hooking operations within the current transaction. Must be called after `ZynterceptTransactionBegin()` and before `ZynterceptAttach()` or `ZynterceptDetach()`.

**Parameters**:

- `Process`: Pointer to a `ZynterceptProcess` structure containing the process identifier and architecture.

**Returns**: `true` if the process was successfully attached, `false` if the transaction is not open or the process identifier is invalid.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

### ZynterceptAttach

```cpp
bool ZynterceptAttach(void** TargetRoutine, void* InterceptionRoutine);
```

Queues a function hook for attachment. The hook will be applied when `ZynterceptTransactionCommit()` is called.

**Parameters**:

- `TargetRoutine`: Pointer to a function pointer that will be redirected to the trampoline after hooking.
- `InterceptionRoutine`: Pointer to the interception function that will be called instead of the original function.

**Returns**: `true` if the hook was successfully queued, `false` if the transaction is not open or parameters are invalid.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Note**: Use the `ROUTINE()` and `INTERCEPTION()` macros for convenience when working with C++ code.

### ZynterceptDetach

```cpp
bool ZynterceptDetach(void** TargetRoutine);
```

Queues a function hook for removal. The hook will be removed when `ZynterceptTransactionCommit()` is called.

**Parameters**:

- `TargetRoutine`: Pointer to the function pointer that was used when attaching the hook.

**Returns**: `true` if the hook was successfully queued for removal, `false` if the transaction is not open or the hook is not currently attached.

**Thread Safety**: Thread-safe. Uses internal mutex for synchronization.

**Note**: Use the `ROUTINE()` macro for convenience when working with C++ code.

### Data Structures

#### ZynterceptProcess

```cpp
typedef struct ZynterceptProcess_ {
    ZynterceptHandle Identifier;
    ZynterceptArchitecture Architecture;
} ZynterceptProcess;
```

Structure containing process information for hooking operations.

**Fields**:

- `Identifier`: Process handle or identifier (platform-specific).
  - Windows: `HANDLE` from `GetCurrentProcess()` or `OpenProcess()`
  - Unix: Process ID from `getpid()` or process identifier
- `Architecture`: Process architecture (`ZYNTERCEPT_ARCHITECTURE_32BIT` or `ZYNTERCEPT_ARCHITECTURE_64BIT`)

#### ZynterceptArchitecture

```cpp
typedef enum ZynterceptArchitecture_ {
    ZYNTERCEPT_ARCHITECTURE_32BIT,
    ZYNTERCEPT_ARCHITECTURE_64BIT,
} ZynterceptArchitecture;
```

Enumeration specifying the target process architecture.

### Macros

#### TRAMPOLINE

```cpp
TRAMPOLINE(Routine);
```

Declares a trampoline pointer for the specified function. Creates a pointer named `Original##Routine` that points to the trampoline after hooking.

**Parameters**:

- `Routine`: Name of the function (without parentheses or parameters).

**Example**:

```cpp
TRAMPOLINE(CalculateSum);
// Creates: static decltype(CalculateSum)* OriginalCalculateSum = CalculateSum;
```

#### ROUTINE

```cpp
ROUTINE(Routine);
```

Returns the address of the function pointer for use with `ZynterceptAttach()` or `ZynterceptDetach()`.

**Parameters**:

- `Routine`: Name of the function (without parentheses or parameters).

**Returns**: Address of the function pointer (`void**`).

**Example**:

```cpp
ZynterceptAttach(ROUTINE(CalculateSum), INTERCEPTION(CalculateSum));
```

#### INTERCEPTION

```cpp
INTERCEPTION(Routine);
```

Returns the address of the interception function for use with `ZynterceptAttach()`.

**Parameters**:

- `Routine`: Name of the interception function (without parentheses or parameters).

**Returns**: Address of the interception function (`void*`).

**Example**:

```cpp
ZynterceptAttach(ROUTINE(CalculateSum), INTERCEPTION(CalculateSum));
```

## Limitations and Considerations

### Function Prologue Requirements

Functions must have a prologue of sufficient size to accommodate the detour jump instruction (5 bytes for x86, 14 bytes for x64). Functions with very short prologues may not be hookable.

### Instruction Relocation

The library automatically relocates instructions from the function prologue to the trampoline. Complex instructions, particularly those with relative addressing, are handled automatically. However, certain edge cases may not be supported.

### Thread Safety

While the transaction API is thread-safe, care must be taken when hooking functions that may be called from multiple threads. The interception functions themselves are not automatically synchronized.

### Process Permissions

Hooking functions in external processes requires appropriate permissions. On Windows, this typically requires administrator privileges or debug privileges. On Unix systems, appropriate permissions depend on the target process ownership and system configuration.

### Memory Allocation

The library allocates memory for trampolines near the target function to ensure that relative jumps remain within range. If memory allocation fails, hooking will fail.

### Recursive Functions

The library supports hooking recursive functions. When calling the original function through the trampoline from within an interception function, the interception will not be triggered again for that call.

## License

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
