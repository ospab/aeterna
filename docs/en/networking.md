# Networking and OSTP

## The network stack

At boot the first supported network card is brought up and configured by DHCP. If DHCP fails,
the address falls back to link-local `169.254.1.1` and the boot log shows a warning.

Protocols: Ethernet, ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS (with `/etc/resolv.conf`, Cloudflare
and Google as defaults), NTP, and a TLS 1.3 client used by `curl`, `tomato` and `ostp`.

```
# ip addr          addresses (lo and eth0), the DHCP fallback is flagged
# ip link          link state, driver, packet and byte counters
# ip route         default route, connected subnet, loopback
# ping -c 3 1.1.1.1
# nslookup ospab.org
# curl https://ipinfo.io
# ntpdate          set the clock from NTP
# netdiag          network card diagnostics and the PCI list
```

Supported cards are listed in [Hardware](hardware.md).

## OSTP

[OSTP](https://github.com/ospab/ostp) is the ospab stealth transport. ospab.os has a built-in
client whose commands follow the Linux `ostp` client.

```
# ostp import ostp://KEY@host:port          save a share link
# ostp import https://host/sub/TOKEN        save a subscription (all its servers)
# ostp sub                                  show the subscription: servers, traffic, refresh
# ostp sub update                           refresh it
# ostp list                                 saved servers; * marks the selected one
# ostp use 2                                select another server (reconnects if connected)
# ostp connect                              connect to the selected server
# ostp status                               session state, transport, counters
# ostp ping -c 3                            ping through the tunnel
# ostp dns example.com                      DNS through the tunnel
# ostp get example.com /                    HTTP request relayed through the server
# ostp close                                disconnect
# ostp check                                validate the saved configuration
# ostp gk -n 2                              generate access keys
```

The configuration is stored in `/etc/ostp/config.json`; on an installed system it survives a
reboot once it has been written to disk (`sync`, or automatically after a few seconds).

Transports: **UDP** and **UoT** (UDP over TCP). Links that require TLS are reported as
unsupported. While the console waits for input it keeps an established session alive with
keepalives; if the session dies, the next `ostp` command reconnects.

Entropy for the handshake comes from the CPU's RDRAND instruction. On a CPU without RDRAND
`connect` refuses unless `--weak-rng` is given (in QEMU use `-cpu max`).

Typing a long link by hand is not necessary: in VMware use Ctrl+V or `ostp import $(clip)`, see
[Shell and tools](shell.md).

Not yet: routing all system traffic through the tunnel (a tunnel network interface).
