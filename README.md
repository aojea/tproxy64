# tproxy64

Proxy transparently IPv6 to IPv4 using tproxy.

Simple and easy to use for containerized environments.

Credit to these 2 projects:

- https://github.com/benjojo/dumb-nat-64
- https://github.com/KatelynHaworth/go-tproxy

## How it works

The progam uses the [Linux Transparent Proxy](https://www.kernel.org/doc/html/v5.8/networking/tproxy.html) functionality to capture the reserved NAT64 prefix  64:ff9b::/96 and "proxy" to the corresponding IPv4 address (embedded in the IPv6 address)

This can be used with public DNS64 servers like [Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns64)


### Implementation details

It installs the following iptables and routing rules and creates a proxy server that listens on an specified port.

```sh
ip6tables -t mangle -N DIVERT
ip6tables -t mangle -A PREROUTING -m socket -j DIVERT
ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
ip6tables -t mangle -A DIVERT -j ACCEPT

ip -6 rule add fwmark 1 lookup 100
ip -6 route add local ::/0 dev lo table 100

ip6tables -t mangle -A PREROUTING -d 64:ff9b::/96 -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
```

