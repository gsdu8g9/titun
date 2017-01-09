TiTun (Titanium Tunnel) is a secure IP tunnel for GNU/Linux. It transmits packets via UDP, encrypted and authenticated with a pre-shared key. TiTun is stateless, NAT and proxy friendly, simple and easy to use.

# WARNING

TiTun is still in early stage. And I am not a crypto expert.

USE AT YOUR OWN RISK.

# Install

You can either build TiTun yourself or download prebuilt binary from GitHub releases.

To build TiTun you need the rust toolchain, which can be installed with [rustup](https://github.com/rust-lang-nursery/rustup.rs). You also need libsodium. On recent Debian/Ubuntu systems, you should be able to install it with:

```
# apt install libsodium-dev
```

Then run

```
$ cargo build --release
```

And TiTun will available be at `target/release/titun`.

The binarys at GitHub releases are statically linked. They should work on any recent x86-64 linux systems.

# Usage

You are expected to have some networking knowledge and system administration skills to use TiTun.

## Generate key

First you need to generate a key. Run
```
$ titun genkey
```

It should print something like:
```
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagvUI="
```

(*WARNING: GENERATE YOUR OWN. DO NOT USE THIS! ACTUALLY THIS IS NOT A VALID KEY.*)

## Try it

Now write config files for the two hosts. One of them must have a UDP port reachable from the other. This host we will refer to as the server, and the other as the client.

Config files are simple yaml files. Start with something like this:

Server config server.yaml:
```
bind: "0.0.0.0:8733"
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagvUI="
config_script: |
   ip link set $TUN up
   ip addr add 192.168.43.1 peer 192.168.43.2 dev $TUN
```

Client config client.yaml: (Substitute `[server-address]` with the actual address of the server.)
```
peer: "[server-address]:8733"
key: "T7DEdB4b0nK6F6hE0/+8SzepNiJ+sFz1AXMYagMzvUI="
config_script: |
   ip link set $TUN up
   ip addr add 192.168.43.2 peer 192.168.43.1 dev $TUN
```

Run
```
# titun tun -c server.yml
```
on the server, and run
```
# titun tun -c client.yml
```

on the client (both as root). You should be able to ping 192.168.43.1 from the client, then able to ping 192.168.43.2 from the server.

It's worth nothing that the server/client distinction is not inherent to TiTun. You can configure both as “server”, bind to a fixed port.

For a full list of configuration options available, see `src/config.rs`.

## Configure the tunnel device with `config_script`

TiTun just transmit packets between the two tun devices. How to use the tun devices is completely up to you. The `config_script` entry is a shell script which will be run after the tunnel device is created. The environment variable `TUN` is set to the name of the tun device.

For example, to connect two networks together, you can use:

server.yml:
```
bind: ...
key: ...
config_script: |
   ip link set $TUN up
   ip addr add 192.168.43.1 peer 192.168.43.2 dev $TUN
   ip route add 192.168.45.0/24 via 192.168.43.2 dev $TUN
```

client.yml:
```
server: ...
key: ...
config_script: |
   ip link set $TUN up
   ip addr add 192.168.43.2 peer 192.168.43.1 dev $TUN
   ip route add 192.168.44.0/24 via 192.168.43.1 dev $TUN
```

To route client internet traffic through the server, use something like:

```
...
config_script: |
   ip link set $TUN up
   ip addr add 10.177.33.7 peer 10.177.33.1 dev $TUN
   ip route add 0.0.0.0/1 dev $TUN
   ip route add 128.0.0.0/1 dev $TUN
```

and setup the server appropriately: iptable rules, sysctl, etc.

## MTU

To avoid IP fragmentation, set the MTU of the tun device to path MTU minus 52 bytes. (20 bytes IP header, 8 bytes UDP header, 24 bytes nonce.).

## Systemd

Systemd is fully supported. An Example systemd service file is provided in the `contrib` dir. TiTun will notify systemd about startup completion with `systemd-notify`.

# Crypto

TiTun uses the awesome [libsodium](https://github.com/jedisct1/libsodium) library for encryption and authentication. Specifically, it uses `crypto_secretbox` with the pre-shared key and a time-based, random nonce. See `src/crypto.rs`.

## Caveats

1. Need to sync time between the two hosts.

2. No forward secrecy.

# Acknowledgment

TiTun is heavily influenced by [fastd](https://projects.universe-factory.net/projects/fastd/wiki). The major problem I have with fastd is that it doesn't seem to work very reliability when there is NAT.

# COPYING

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
