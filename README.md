# TiTun

[![Build Status](https://travis-ci.org/sopium/titun.svg?branch=master)](https://travis-ci.org/sopium/titun)

TiTun (Titanium Tunnel) is a simple, fast and easy to use IP tunnel for linux. It transmits packets via UDP, encrypted and authenticated with a pre-shared key. A distinguishing feature of TiTun is NAT and proxy friendliness: most other VPN software I tried have problem working with my ISP where UDP NAT mapping frequently changes.

## Status

The current protocol is [not very sound](#caveats), and TiTun has not been audited/reviewed. It should work well as a obfuscation layer though.

If you need better performance and/or security, [wireguard](https://www.wireguard.io/) seems very promising.

## Install

You can either build TiTun from source or download binarys or deb packages from [GitHub releases](https://github.com/sopium/titun/releases).

To build TiTun you need the rust toolchain, which can be installed with [rustup](https://github.com/rust-lang-nursery/rustup.rs). You also need libsodium. It may be available from your distro's package manager. Or you can build it yourself.

Get the code and run

```
$ cargo build --release
```

And TiTun will available be at `target/release/titun`.

## Usage

TiTun can be used to establish a secure IP tunnel between two linux hosts, provided that one of them has a UDP port reachable from the other.

### Key generation

Run

```
$ titun genkey
```

to generate a key for TiTun. The two hosts must use a same key.

A TiTun key looks like:

```yaml
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagvUI="
```

i.e. 32 random bytes encoded in base64.

### Configuration

TiTun config files are written in [yaml](http://yaml.org/). The following configuration options are supported:

* `bind`: Address and port to bind to.
* `peer`: Peer address and port.
* `key`: Encryption/authentication key.
* `on_up`: A shell script that will be run after the tun device is created. Use this to bring the device up and set ip address, MTU, and add routes, etc.
* `on_down`: A script that will be run when the tun device is about to be closed.
* `bufsize`: Size of buffer when reading from tun device or receiving from socket.
* `max_diff`: Maximum timestamp differences allowed, in milliseconds.
* `dev_name`: Name of tun device.

At minimum, {bind or peer} and key must be specified.

Here is an example pair of config files:

Server:

```yaml
bind: "1.2.3.4:5678"
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagvUI="
on_up: |
  ip link set $TUN up mtu 1280
  ip addr add 192.168.9.1 peer 192.168.9.2 dev $TUN
```

Client:

```yaml
peer: "1.2.3.4:5678"
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagvUI="
on_up: |
  ip link set $TUN up mtu 1280
  ip addr add 192.168.9.2 peer 192.168.9.1 dev $TUN
```

### Command Line Interface

It's just:

```
# titun tun -c config.yml
```

The `RUST_LOG` environment variable can be used to control logging. See [env-logger](https://doc.rust-lang.org/log/env_logger/).

### MTU

To avoid IP fragmentation, set the MTU of the tun device to path MTU minus 68 bytes. (20 bytes IP header, 8 bytes UDP header, 16 bytes nonce, 16 bytes auth tag, 8 bytes timestamp).

### Systemd

Systemd is fully supported. An example systemd service file is provided in the `systemd` dir. TiTun will notify systemd about startup completion with `systemd-notify`.

If you are using the debian package, just put config files, e.g. `tunnel.yml`, at `/etc/titun/`, and

```
# systemctl start titun@tunnel
```

If you are building from source, copy `systemd/titun@.service` to `/etc/systemd/system/`, copy `titun` to `/usr/local/bin`, and the rest is the same.

## Protocol

TiTun uses the awesome [libsodium](https://github.com/jedisct1/libsodium) library for encryption and authentication. Specifically, it uses `crypto_secretbox` with the pre-shared key and random nonces. A timestamp is appended to packets before encryption to mitigate replay attack. See `src/crypto.rs`.

### Caveats

1. Need to sync time between the two hosts.

2. No forward secrecy.

## Performance

I get 700Mbps+ throughput with `iperf3` between my Haswell Xeon-E3 desktop computer and a local virtual machine.

## Contributing

I built TiTun primarily for my personal usage, (and to try and learn rust), so it is very limiting. If someone can write a good cross platform library for tun device creation/management, I would happily port TiTun over to make it cross platform.

Issues and pull requests are welcome.

## Acknowledgment

TiTun is heavily influenced by [fastd](https://projects.universe-factory.net/projects/fastd/wiki). Fastd doesn't work very reliability when there is NAT though, probably becuase it lacks a keep-alive mechanism?

## License: GPL v3+

```
Copyright 2017 Sopium

TiTun is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TiTun is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TiTun.  If not, see <https://www.gnu.org/licenses/>.
```
