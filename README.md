# SecurePassGen-rs

A Rust implementation of [Tetsuo's SecurePassGen](https://github.com/7etsuo/SecurePassGen), a cryptographically secure password generator that provides high-entropy passwords with configurable requirements.

## About

This is a Rust reimplementation of the original C version, maintaining all security features while leveraging Rust's safety guarantees and cross-platform compatibility through ChaCha20 CSPRNG.

### Security Features

* Uses ChaCha20 CSPRNG for cryptographically secure random number generation
* Implements rejection sampling to eliminate modulo bias
* Enforces minimum character type requirements
* Uses Fisher-Yates shuffle for uniform distribution
* Securely clears sensitive data from memory
* Configurable password requirements
* Entropy pool for efficient random number generation

## Building from Source

### Prerequisites

* Rust toolchain (rustc, cargo)
* Standard build tools for your platform

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Teach2Breach/SecurePassGen-rs.git
    ```

2. Navigate to the project directory:

    ```bash
    cd SecurePassGen-rs
    ```

3. Build the project:

    ```bash
    cargo build --release
    ```

4. The binary will be located in the `target/release` directory.

### Usage

```bash
    ./target/release/SecurePassGen-rs.exe 16
```

This will generate a password of specified length (minimum 12 characters) that includes:
* At least one uppercase letter
* At least one lowercase letter
* At least one number
* At least one special character

## Configuration

You can modify the following constants in `src/main.rs`:

* `UPPERCASE`: Set of uppercase letters
* `LOWERCASE`: Set of lowercase letters
* `NUMBERS`: Set of numbers
* `SYMBOLS`: Set of special characters


Password requirements can be adjusted by modifying the `PasswordRequirements` struct initialization in `main()`.

## Security Considerations

1. The generated passwords are intended for use as user credentials and should be treated as sensitive data
2. The program securely clears sensitive data from memory after use
3. The random number generation uses ChaCha20, a cryptographically secure PRNG
4. The program enforces a minimum password length of 12 characters for security

## Differences from Original Implementation

* Uses ChaCha20 instead of platform-specific crypto APIs for better cross-platform compatibility
* Implemented in Rust for memory safety and thread safety
* Takes advantage of Rust's type system and ownership model
* Maintains equivalent security properties while using more idiomatic code

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Original work Copyright (c) 2024 Tetsuo<BR>
Modified work Copyright (c) 2024 Teach2Breach

## Acknowledgments

* Original implementation by [Tetsuo](https://github.com/7etsuo/SecurePassGen)
