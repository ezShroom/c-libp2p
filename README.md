# libp2p-c (WIP)

Implementation of [Libp2p](https://libp2p.io/) specification in C.

## Building the Project

To build the project, you will need to have CMake installed. Follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/Pier-Two/libp2p-c.git
    cd libp2p-c
    ```

2. Create a build directory and navigate into it:
    ```sh
    mkdir build && cd build
    ```

3. Run CMake to configure the project:
    ```sh
    cmake ..
    ```

4. Build the project:
    ```sh
    cmake --build .       
    ```

5. Run the tests:
    ```sh
    ctest
    ```

## Project Structure

- `src/`: Contains the source code for the library.
- `include/`: Contains the public headers for the library.
- `tests/`: Contains the test code for the library.
- `benchmarks/`: Contains the benchmark code for the library.
- `CMakeLists.txt`: The CMake build script for the project.


## License

MIT License - see [LICENSE-MIT.md](LICENSE-MIT.md).

