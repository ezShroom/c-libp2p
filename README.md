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

## Third-party Libraries

This project includes or makes use of the following third-party libraries:

- [libtomcrypt](https://github.com/libtom/libtomcrypt) (included as a git submodule):
  - Licensed under the [LibTom License (Public Domain/Unlicense)](http://unlicense.org/).

- [secp256k1](https://github.com/bitcoin-core/secp256k1):
  - Licensed under the [MIT License](https://opensource.org/licenses/MIT).

- [sha3](https://github.com/pablotron/sha3):
  - Licensed under the [MIT-0 License](https://opensource.org/license/mit-0/).

- [WjCryptLib](https://github.com/WaterJuice/WjCryptLib):
  - Licensed under the [Unlicense (Public Domain)](http://unlicense.org/).

