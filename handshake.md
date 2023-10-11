
# Stellar Handshake Process

The handshake process in Stellar involves establishing a TCP connection and subsequently exchanging "Hello" and "Auth" messages.

## Initial Setup:

Prior to initiating the connection, it's essential to have a persistent `ed25519` secret key, termed the `seed`. From this `seed`, we aim to derive a `persistent_public_key` and a `signing_key`:
1. Derive from the seed key using: `(persistent_public_key, _) = crypto_sign_seed_keypair(seed)`.
2. Construct the `signing_key` as: `[seed + persistent_public_key]`.

## TCP Connection Establishment:

Once the initial setup is completed, we proceed to establish a TCP connection with the target node. Upon a successful connection:
1. Generate a random `per_connection_secret_key` and compute its corresponding `per_connection_public_key = crypto_scalarmult_base(per_connection_secret_key)`.
2. Prepare the "Hello" message for transmission.

## Constructing the "Hello" Message:

The "Hello" message incorporates various data types, including raw data (ledger and overlay versions), hashed data (`network_id`), and other signed/encrypted data (authentication certificate). The primary components of this message are:
1. `sha256(network_id)`
2. **Auth Certificate**:
    - This structure includes the `per_connection_public_key`, the certificate's `expiration`, and a `signature`. To construct the missing components we do:
      1. create `expiration = time.now() + 60`minutes.
      2. create `signature`. For that we do:
         1. Generate `signature_data` using: `sha256([network_id + [3] + expiration + per_connection_public_key])`.
         2. Sign this data with the `signing_key`: `signature = crypto_sign_detached(signature_data, signing key)`.
3. `persistent_public_key`
4. `local_nonce = sha256(random bytes[32])`.

Following the construction, archive the message using `bytes_to_send = archive(hello message.encoded())`.\
Send th archive over TCP.

Next, await the node's archived "Hello" message.\
Upon its receipt, unarchive and decode it.
Then do `hello.cert` verification:
   1. Ensure `time.now() < cert.expiration`.
   2. Reconstruct the signature hash: `hash = sha256([self.network_id + [3] + cert.expiration + cert.per_connection_public_key])` 
   3. verify with `crypto_sign_verify_detached(cert.signature, hash, hello.persistent_public_key)`.

Extract and store the `remote_nonce` and `remote_public_key` from the message.

Create `local_sequence` and `remote_sequence` properties and set them to zero.

In order to construct any further messages, we need to generate the `sending_mac_key` and `receiving_mac_key`. For that we do the following actions:
## MAC Key Generation:

For both `sending_mac_key` and `receiving_mac_key` generation:
1. Calculate `shared_key` by doing the following:
    1. create `shared_secret_key = scalarmut(self.per_connection_secret_key, remote_public_key)`.
    2. Create `message = [shared_secret_key + self.per_connection_public_key + remote_public_key]`.
    3. `return create_sha256_hmac(message, zero_salt)`.
2. With `shared_key` available, calculate `sending_mac_key` and `receiving_mac_key`. Execute the subsequent steps twice — once for sending and once for receiving:
    1. Create a `message = if is_sending [[0] + local_nonce + remote_nonce + [1]] else [[1] + remote_nonce + local_nonce + [1]]`.
    2. `return create_sha256_hmac(message, shared_key)`.

## Constructing the "Auth" Message:

1. Encode "Auth" message `message.encoded()`
2. All archived messages, but not the one that contains "Hello" message, have `sequence` and `mac` properties that need to be verified upon receiving. For MAC generation:
    1. create a `message = [local_sequence + message.encoded()]`.
    2. Compute the MAC: `mac = create_sha256_hmac(data, sending_mac_key)`.

Archive the message `bytes_to_send = archive(local_sequence, auth message.encoded(), mac)` and transmit it over TCP. Increment `local_sequence` by one and await the node's archived "Auth" message. Upon receipt:
1. Unarchive `received_bytes` into its components: `(unarchived_remote_sequence, message.encoded(), mac) = unarchive(received_bytes)`.
2. Verify the message the unarchived message by doing the following:
    1. `remote_sequence == unarchived_remote_sequence`.
    2. Verify hmac by checking `verify_sha256_hmac(mac, receiving_mac_key, message.encoded())`.
    3. Increment `remote_sequence` by one.

The handshake process is now concluded, providing a secure communication channel within the Stellar network.
