# Polyrhoé Protocol Specification

*Version 1.0.0*

## Abstract

Polyrhoé (PR) is a lightweight protocol for secure multiplexed shell sessions over networks. It implements Iroh for authenticated encryption, providing confidentiality and integrity.

## 1. Protocol Codes

The protocol defines a set of standardized codes to identify packet types. Each code is represented by a 1-byte unsigned integer:

`0x00` **(DISCONNECT)**  
Terminates the client connection.

`0x01` **(COMMAND)**  
Transmits an encrypted command to be executed by the server.

`0x02` **(COMMAND_OUTPUT)**  
Contains incremental output from server command execution.

`0x03` **(COMMAND_END)**  
Signals completion of command execution with no further output.

`0x04` **(REFRESH_SESSION)**  
Reset the session state, typically when switching connections.

## 2. Packet Structure

All protocol communications conform to the following binary structure:

```
┌───────────────────┬────────────┬─────────────────────┐
│   Packet Length   │    Code    │      Message        │
│     (4 bytes)     │  (1 byte)  │     (variable)      │
└───────────────────┴────────────┴─────────────────────┘
```

- **Packet Length**  A 4-byte unsigned integer in network byte order (big-endian) representing the total packet length. This field remains unencrypted.

- **Code**  A 1-byte unsigned integer identifying the packet type as defined in Section 1, determining how the receiving endpoint should interpret the encrypted payload.

- **Message**  A variable-length field containing the authenticated encrypted payload. This data is produced using the QUIC algorithm, providing both confidentiality and integrity verification.