# Cryptographic Schemes Performance Comparison

## Project Overview

This Java project focuses on the implementation and performance evaluation of various cryptographic schemes proposed in academic literature, alongside our novel scheme. The implemented schemes include:

*   Ali et al.
*   Lee et al.
*   Ma et al.
*   Tian et al.
*   Tseng et al.
*   Our Proposed Scheme

## Project Structure

The source code is organized into modular directories, each corresponding to a cryptographic scheme:

```
src/
├── Ali11/         # Implementation of Ali et al. scheme
├── Lee9/          # Implementation of Lee et al. scheme
├── Ma13/          # Implementation of Ma et al. scheme
├── our/           # Implementation of our proposed scheme
├── Tian22/        # Implementation of Tian et al. scheme
└── Tseng21/       # Implementation of Tseng et al. scheme
```

## Dependencies

The project relies on the following JAR files, which are located in the `jar/` directory:

### Core Libraries (JPBC)

The Java Pairing-Based Cryptography (JPBC) library provides the fundamental pairing operations:

*   **jpbc-api-2.0.0.jar** - Core API
*   **jpbc-crypto-2.0.0.jar** - Cryptographic implementations
*   **jpbc-pbc-2.0.0.jar** - Bindings to the PBC library
*   **jpbc-plaf-2.0.0.jar** - Platform abstraction layer
*   **jpbc-mm-2.0.0.jar** - Matrix math utilities
*   **jpbc-benchmark-2.0.0.jar** - Benchmarking tools

### Utility Libraries

*   **commons-codec-1.17.1.jar** - Apache Commons Codec for encoding/decoding operations.

## Building and Running

To compile and execute the performance comparison, follow these steps:

1.  **Set Up Classpath**: Ensure all JAR files in the `jar/` directory are included in your project's classpath.
2.  **Compile the Source Code**:
    ```bash
    javac -cp "jar/*" src/**/*.java
    ```
    *(Note: The `**` wildcard is used to recursively compile all `.java` files under `src/`.)*
3.  **Run the Benchmark**:
    ```bash
    java -cp "src:jar/*" [fully.qualified.MainClassName]
    ```
    Replace `[fully.qualified.MainClassName]` with the actual main class (e.g., `our.SchemeComparison`).

## Performance Comparison Metrics

The project's benchmarking module is designed to compare the schemes across several key performance indicators:

*   **Computational Efficiency**: Execution time of key operations (e.g., setup, encryption, decryption).
*   **Memory Footprint**: JVM memory usage during runtime.
*   **Throughput**: Number of operations processed per unit time.
*   **Scheme-Specific Overheads**: Any additional costs unique to a particular scheme's design.

## Notes

*   **JPBC Version**: This project is built using JPBC version 2.0.0. Compatibility with other versions is not guaranteed.
*   **Modularity**: Each scheme is implemented in its own directory to promote code isolation, reusability, and ease of maintenance.
*   **Proposed Scheme**: The `our/` directory contains the source code for the novel cryptographic scheme introduced in this work.
