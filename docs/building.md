# Building libp2p-c

libp2p-c uses CMake and requires a C compiler. The steps below summarize the process.

1. Clone the repository and enter it:
   ```sh
   git clone https://github.com/Pier-Two/libp2p-c.git
   cd libp2p-c
   ```
2. Create a build directory:
   ```sh
   mkdir build
   ```
3. Configure with CMake:
   ```sh
   cmake -S . -B build
   ```
   Optional flags such as sanitizers can be enabled at this stage. See the project [README](../README.md) for the full list.
4. Build the library and tests:
   ```sh
   cmake --build build
   ```
5. Run the tests using CTest:
   ```sh
   ctest --test-dir build
   ```

The resulting static library and public headers are placed in the `lib/` and `include/` directories.
