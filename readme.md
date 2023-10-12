
### Connector to the Stellar Node in Rust

[Stellar blockchain node source code](
https://github.com/stellar/stellar-core)

The app is minimalistic. By default, it connects to a hardcoded [MAINNET stellar node](https://stellarbeat.io/nodes/GAAV2GCVFLNN522ORUYFV33E76VPC22E72S75AQ6MBR5V45Z5DWVPWEU?center=1), executes handshake, prints the result and ends.

To run this app:
1. `rust version 1.71`
2. `cargo run`

To understand the handshake process, refer to [handshake](handshake.md) in the root of the project.

What's not included:
1. Unit tests. The code is written to be easily unit-tested because it eliminates all random dependencies.
2. When the Stellar Node, not the app is the one who initializes a connection.
2. Handling `Error` as well as any other messages from node.
3. Reading the configuration from file. The configuration constants are hardcoded as `mainnet` and `local`, but it's easy to add your own config.
4. Logging.
5. Timeout for waiting for messages from TCP.
6. Running a tcp connection in a separate task.
7. Code comments.

Upon request, it's possible to provide the details on how to run a local stellar node to actually read the logs from it or implement all the above features.