# tproxy64

Proxy transparently IPv6 to IPv4 using tproxy.

Simple and easy to use for containerized environments.

Credit to these 2 projects:

- https://github.com/benjojo/dumb-nat-64
- https://github.com/KatelynHaworth/go-tproxy

```sh
ip6tables -t mangle -N DIVERT
ip6tables -t mangle -A PREROUTING -m socket -j DIVERT
ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
ip6tables -t mangle -A DIVERT -j ACCEPT

ip -6 rule add fwmark 1 lookup 100
ip -6 route add local ::/0 dev lo table 100

ip6tables -t mangle -A PREROUTING -d 64:ff9b::/96 -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
```

