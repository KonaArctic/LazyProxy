Lazy Transparent Proxy
======================
Easily convert any SOCKS or HTTP proxy into a transparent proxy.

Run `go run github.com/KonaArctic/LazyProxy IPADDR PROXYURL`, then point DNS to IPADDR.
That's it!

Additional options:
-   -setuid=N               : Set user ID to N when possible
-   -resolv=DOMAIN=IPADDR   : DOMAIN will resolve to IPADDR

Lazy Proxy sniffs virtual hosts and uses DNS timing information to forward traffic.

Caveats
-------
-   Does't work with direct IP connections.
-   Bring your own DHCP server, or configure DNS manually.

