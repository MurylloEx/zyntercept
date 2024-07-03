# Create from cmake.toml

```sh
# Enter in project root folder
cd zyntercept

# Generate cmake files
cmkr gen
```

# Debug build from cmake (Windows/Visual Studio)

```sh
# Enter in project root folder
cd zyntercept

# Configure the debug build
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B "build32" -D CMAKE_BUILD_TYPE=Debug # For x86 (CISC)
cmake -G "Visual Studio 17 2022" -A x64 -S . -B "build64" -D CMAKE_BUILD_TYPE=Debug # For x64 (CISC)

# Actually build the binaries
cmake --build build32/ # For x86 (CISC)
cmake --build build64/ # For x64 (CISC)
```

# Release build from cmake (Windows/Visual Studio)

```sh
# Enter in project root folder
cd zyntercept

# Configure the release build
cmake -G "Visual Studio 17 2022" -A Win32 -S . -B "build32" -D CMAKE_BUILD_TYPE=Release # For x86 (CISC)
cmake -G "Visual Studio 17 2022" -A x64 -S . -B "build64" -D CMAKE_BUILD_TYPE=Release # For x64 (CISC)

# Actually build the binaries
cmake --build build32/ # For x86 (CISC)
cmake --build build64/ # For x64 (CISC)
```
