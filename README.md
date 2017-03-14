# TiTun

[![Build Status](https://travis-ci.org/sopium/titun.svg?branch=wg)](https://travis-ci.org/sopium/titun)

This is an effort to write a secure, compatible, cross-platform and reasonably fast user-space implementation of WireGuard in Rust.

It is nowhere near complete/stable/secure. But basic functionality seems to work. Review and testing is welcome.

## TODO

Checked means that there are people working on it. Completed items should be removed from here.

Pull requests are welcome!

### Capability

- [ ] ICMP no route to host / unreachable reply.
- [ ] Queue packets during handshake initiation.
- [ ] Send cookie reply packets, i.e., activate the DoS mitigation mechanism, when under load. When???
- [ ] Persistent keep-alive.
- [ ] Zero padding IP packets.

### Cross Platform

- [ ] Support more platforms, i.e., write TUN device wrappers for more platforms.

### UI

- [ ] Work with the `wg` tool, i.e., impl [this](https://www.wireguard.io/xplatform/).

### Testing

- [ ] More tests.

### Performance

- [ ] Instrumenting. For example, insert `Instant::now()`s between parsing, table lookup, encryption/decryption, locking, etc., so that we know where the threads are spending time on.
- [ ] Reuse buffers, and move buffers to the stack.
- [ ] `SO_REUSEPORT` sockets, multi-queue tun fds.
