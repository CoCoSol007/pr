# Polyrhoé Protocol Specification

*Version 1.0.0*

## Abstract

Polyrhoé (PR) is a lightweight protocol for secure multiplexed shell sessions over networks. It implements AES-256-GCM for authenticated encryption and X25519 Elliptic Curve Diffie-Hellman for key exchange, providing confidentiality, integrity, and protection against replay attacks with minimal overhead.

## 1. Protocol Codes

The protocol defines a set of standardized codes to identify packet types. Each code is represented by a 1-byte unsigned integer:

`0x00` **(DISCONNECT)**  
Terminates the client connection.

`0x01` **(PUBLIC_KEY_REQUEST)**  
Initiates key exchange by requesting the server's public key.

`0x02` **(PUBLIC_KEY_RESPONSE)**  
Delivers the server's ephemeral public key for session establishment.

`0x03` **(COMMAND)**  
Transmits an encrypted command to be executed by the server.

`0x04` **(COMMAND_OUTPUT)**  
Contains incremental output from server command execution.

`0x05` **(COMMAND_END)**  
Signals completion of command execution with no further output.

`0x06` **(REFRESH_SESSION)**  
Reset the session state, typically when switching connections.

## 2. Packet Structure

All protocol communications conform to the following binary structure:

```
┌───────────────────┬────────────┬──────────────┬─────────────────────┐
│   Packet Length   │    Code    │    Nonce     │     Ciphertext      │
│     (4 bytes)     │  (1 byte)  │  (12 bytes)  │     (variable)      │
└───────────────────┴────────────┴──────────────┴─────────────────────┘
```

- **Packet Length**  A 4-byte unsigned integer in network byte order (big-endian) representing the total packet length. This field remains unencrypted.

- **Code**  A 1-byte unsigned integer identifying the packet type as defined in Section 1, determining how the receiving endpoint should interpret the encrypted payload.

- **Nonce**  A 12-byte cryptographically secure random value generated uniquely for each packet. This nonce (number used once) prevents replay attacks.

- **Ciphertext**  A variable-length field containing the authenticated encrypted payload. This data is produced using the AES-256-GCM algorithm with the established shared secret key and the packet-specific nonce, providing both confidentiality and integrity verification.