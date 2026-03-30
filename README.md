# Conclave
---

## Overview
**Conclave** is a high-performance, end-to-end encrypted (E2EE) chat suite. It bypasses standard JSON-over-WebSocket overhead by using a custom binary protocol and a multi-language stack designed for low-latency message routing.

### Project Post-Mortem
This project began as a networking lab concept and evolved into a deep dive into the complexities of asynchronous socket management. 
> **Reflections:** If I were to re-attempt this, I would replace the "God Functions" (routing all message types) with a polymorphic command pattern or fixed-width structs to better align data and prevent the manual offset-math headaches encountered during development.

## The Stack
* **Core Engine (C++20):** Handles raw socket management using `epoll` for $O(1)$ event scaling. It manages segment logic and high-speed binary broadcasting.
* **Communication Bridge (FastAPI):** Acts as the management layer, handling HTTP-to-Binary translation and user authentication via HMAC tokens.
* **Security Layer (Web Crypto API):** Implements client-side AES-256-GCM encryption.

---

## The Protocol: Custom Binary Framing
To minimize overhead, Conclave uses a specific binary packet structure. This allows the C++ core to route packets purely by reading the header, without ever needing to parse complex strings or JSON.

### Message Format (Data Transmission)

| Offset | Field | Size | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | **Length** | 4B | Total packet size (Big Endian) |
| `0x04` | **Type** | 1B | Message Opcode (0x00) |
| `0x05` | **Room ID** | 4B | Target Network Segment |
| `0x09` | **User ID** | 4B | Public Sender Identity  |
| `0x0D` | **Payload** | NB | AES-GCM Ciphertext |

### Command Format (Control Plane)

| Type | Code (1B) | Payload (NB) |
| :--- | :--- | :--- |
| **JOIN** | 0 | `[RoomId(4)] [UserId(4)] [Password(N)]` |
| **LEAVE** | 1 | `[RoomId(4)] [UserId(4)]` |
| **CREATE** | 2 | `[name~password (N)]` |
| **DESTROY** | 3 | `[RoomId(4)] [Password(N)]` |
| **DISCONNECT** | 4 | `[UserId(4)]` |
| **CONNECT** | 5 | `[TabId(N)]` |
| **VERIFY** | 6 | `[RoomId(4)] [UserId(4)]` |

## Security Implementation: Zero-Knowledge
Conclave is designed so that the server is "blind." The backend only handles routing metadata; the actual conversation content remains a cryptographic black box.

1. **Key Derivation:** Uses **PBKDF2** with 100,000 iterations of **SHA-256** to turn segment passwords into high-entropy cryptographic keys.
2. **Authenticated Encryption:** Uses **AES-256-GCM**.
   $$ C = E_{AES-GCM}(K, IV, P) $$
3. **Integrity Checks:** If a packet is tampered with in transit, the GCM tag verification fails at the client level, and the message is rejected before display.

## Technical Challenges
* **The Bridge Handshake:** Synchronizing a stateless HTTP environment with a stateful C++ socket server required a custom HMAC-signed session token flow to maintain persistent identity across reloads.
* **The Reaper Loop:** A background housekeeping loop was designed to prune stale resources (Rooms/Users). However, it introduced race conditions that impacted session registration. To prioritize stability and low latency, resource management was shifted to an event-driven model.

### Known Constraints
* **Reconnection Sync:** Room population data may require a manual refresh upon rejoining an existing segment.
* **Resource Lifespan:** Without the active Housekeeping loop, server-side resource pruning is currently a manual administrative task.

## How to Run
1. **Compile Core:** `g++ -std=c++23 src/main.cpp -o server -I include -I external`
2. **Execute:** `./run.sh`
3. **Access Control Plane:** Connect via browser on `port 8000`