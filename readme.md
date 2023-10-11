
### Stellar node handshake process implemented in Rust.


Stellar core source code:
https://github.com/stellar/stellar-core

To run this app:
1. `rust version 1.71`
2. `cargo run`

To understand the handshake process, refer to `handshake.md` in the root of the project.

What's not included:
1. Unit tests. The code is written to be easily unit-tested because it eliminates all random dependencies.
2. Handling `Error` as well as any other messages from node.
3. Logging.
4. Timeout for waiting for messages from TCP. 
5. Running a tcp connection in a separate task.
6. Code comments