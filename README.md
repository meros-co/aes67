# meros-aes67

Two small, portable C11 libraries for audio-over-IP devices:

- **`aes67/`** (`meros::aes67`): AES67 / SMPTE ST 2110-30 RTP receive and transmit, L16/L24 framing,
  a timestamp-indexed playout ring, SDP generation and parsing, and SAP announcement. On Linux, receive
  uses `recvmmsg`, `epoll` and kernel timestamps. Elsewhere, each stream has its own socket and is read
  with `poll`.
- **`mdns/`** (`meros::mdns`): DNS-SD over multicast DNS, the device's half. It announces the device's
  own services (for example `_nmos-node._tcp`) and browses for others (`_nmos-register._tcp`) with one
  socket and no system daemon.

Neither library depends on anything beyond the platform's sockets and threads.

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

The socket tests use multicast on loopback and skip themselves where the OS doesn't deliver it.

## Use

Add the repository as a subdirectory, and link the targets:

```cmake
add_subdirectory(path/to/meros-aes67)
target_link_libraries(my_app PRIVATE meros::aes67 meros::mdns)
```

Headers are included as `<aes67/rx.h>`, `<aes67/tx.h>`, `<aes67/sdp.h>`, `<aes67/rtp.h>` and
`<mdns/mdns.h>`.

Used by Manifold (a digital mixing console) and Inlet (a virtual AES67 sound card).

## Licence

Copyright (C) 2026 Meros Inc. Licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`). See [LICENSE](LICENSE).
