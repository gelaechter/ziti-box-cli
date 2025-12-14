# About

This CLI Utility let's you manage Ziti Boxes.

Ziti Boxes are Linux Router boards that act as an entry into an OpenZiti network.
This CLI utility intends to make the creation of disk images and for flashing these as easy as possible.

## Building from source

This program is written in rust.

Building this program requires a [rust toolchain](https://rust-lang.org/tools/install/).
It makes use of the [error_in_core feature](https://github.com/rust-lang/rust/issues/103765), meaning at the time of writing it [requires a nightly toolchain](https://rust-lang.github.io/rustup/concepts/channels.html#working-with-nightly-rust).

1. **Clone the repo**
    ```shell
    git clone https://github.com/gelaechter/ziti-box-cli
    ```

2. **Go into it**
    ```shell
    cd ziti-box-cli
    ```

4. **Either build the project**
    ```shell
    cargo build --release
    ```
    *This should result in a binary at `target/release/zitibox`*

    **Or directly install it using cargo**
    ```shell
    cargo install --path .
    ```
    *This should compile and install the binary into `$HOME/.cargo/bin`.
     It should then be available in your shell.*
