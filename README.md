# Create from cmake.toml

```sh
# Enter in project root folder
cd zyntercept

# Generate cmake files
cmkr gen
```

# Build from cmake

```sh
# Enter in project root folder
cd zyntercept

# Configure the build
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Debug

# Actually build the binaries
cmake --build build/

# Configure a release build
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Release

# Build release binaries
cmake --build build/
```

