# ndhs
Copyright 2011-2024 Nicholas J. Kain.
See LICENSE for licensing information.

## Introduction

ndhs is a DHCPv4 and DHCPv6 server that also provides IPv6 router
advertisements.  It is intended to be run on a router; IPv6 assumes that
the default gateway for a network will provide router advertisements.

ndhs has been designed to be secure and function with minimal privilege.

Because the implementation is relatively clean and modular, it should
also be easy to extend for custom applications, as well as easy to audit
for correctness.

## Requirements

* Linux kernel
* GCC or Clang
* For developers: [Ragel](https://www.colm.net/open-source/ragel)

## Standard Usage

Compile and install ndhs.
* Build ndhs: `make`
* Install the `ndhs` executable in a normal place.  I would
  suggest `/usr/sbin` or `/usr/local/sbin`.

Set up the user account and chroot directory for ndhs.  Example:
```
$ su -
# umask 077
# groupadd ndhs

# useradd -d /var/lib/ndhs -s /sbin/nologin -g ndhs ndhs

# umask 077
# mkdir -p /var/lib/ndhs/store
# chown root.root /var/lib/ndhs
# chmod a+rx /var/lib/ndhs
# cd /var/lib/ndhs

# mkdir dev
# mknod dev/urandom c 1 9
# mknod dev/null c 1 3
# chown -R root.root dev
# chmod a+rx dev
# chmod a+r dev/urandom
# chmod a+rw dev/null

# chown ndhs.ndhs store
# chmod 700 store
```
Set up a configure file.  See below for more information.  The default
location for a configure file is `/etc/ndhs.conf`.

Run ndhs.  Use `ndhs --help` to see all possible options.  I strongly suggest
running ndhs under some sort of process supervision, such as
[s6](http://www.skarnet.org/software/s6).  This will allow for reliable
functioning in the case of unforseen or unrecoverable errors.

## Configuration Format

Comments are denoted by the POSIX-style `#` comment marker and may follow
any command, so long as the `#` is separated from the final argument
by at least one space or tab.  Comments may also start at the beginning
of a line, as one would expect.

### Global Values
```
user <username>
chroot <path>
bind4 <interface_name>...
bind6 <interface_name>...
default_preference <value>
default_lifetime <seconds>
s6_notify <fdnum>
```

`user` specifies the username of the account that ndhs will switch to
after performing initial configuration.  It must be a non-root account,
and must have read/write access to the `/store` subdirectory of the
chroot directory.

`chroot` specifies the path to the directory that will serve as the root
of the chroot jail for ndhs.  The directory should be owned by root,
and should not be writable by any other user.

`bind4` specifies a list of interfaces on which ndhs will provide dhcp4
service.

`bind6` specifies a list of interfaces on which ndhs will provide dhcp6
and router advertisement services.

`default_preference` specifies the value of the Preference Option for
dhcp6.  It must be between `0` to `255` inclusive and defaults to `0`
if not specified.  A DHCP6 client will prefer to choose responses from
the server with the highest preference value if both servers provide
valid DHCP6 replies.  This statement takes effect for all subsequent
`interface` keywords.

`default_lifetime` specifies the duration in seconds for which dhcp
leases will be valid.

`s6_notify` specifies the file descriptor number to which a newline will be
written after ndhs begins processing requests.

### Interface-specific Values
```
interface <interface_name>
v4 <mac_address> <ipv4_address>
v6 <duid> <iaid> <ipv6_address>
gateway <ipv4_address>
dns_server <ip_address>...
dns_search <fully_qualified_hostname>...
ntp_server <ip_address>...
dynamic_range <ipv4_address> <ipv4_address>
dynamic_v6
```

`interface` is a toggle.  It instructs ndhs that all subsequent
interface-specific options will apply to that interface.  Only one
interface can be modified by these options at a time.

`v4` specifies a static lease for a dhcp4 client.  The client is
determined by its mac address, which is specified in the standard
`aa:bb:cc:dd:ee:ff` format.  The ipv4 address is specified by the typical
dotted-decimal fomat.

`v6` specifies a static lease for a dhcp6 client.  The client is
determined by its duid and iaid.  The duid is specified as either a
string of hexadecimal digits specifying a byte sequence, or as a string
of two-hexadecimal digits delimited by `-`, as is typical for the Windows
`ifconfig /all` command.  The iaid is specified by a string of decimal
digits corresponding to a 32-bit unsigned value.  The ipv6 address is
specified by the typical hexadecimal string delimited by `:`.

`dns_server` specifies a list of dns servers for the address.  The ip
addresses are in the typical string representations for ipv4 or ipv6
addresses.  Multiple addresses are delimited by spaces or tabs.  Only
the most recent `dns_server` option for an interface has any effect.

`ntp_server` specifies a list of ntp servers for the address.  The ip
addresses are in the typical string representations for ipv4 or ipv6
addresses.  Multiple addresses are delimited by spaces or tabs.  Only
the most recent `ntp_server` option for an interface has any effect.

`dynamic_range` enables ipv4 dynamic lease assignment for the interface
and specifies the both-sides inclusive range of ipv4 addresses that
will be used for dynamic lease assignment.  When leases are assigned,
an unused address from this range will be chosen randomly.

`dynamic_v6` enables ipv6 dynamic lease assignment for the interface.
When leases are assigned, an unused address will be chosen randomly.
The prefix of the range is determined at program start by querying the
Linux kernel netlink interface.

### Example Configuration
```
user ndhs
chroot /var/lib/ndhs
bind4 eth0 eth1
bind6 eth0
default_lifetime 3600

# Supports both ipv6 and ipv4.
interface eth0
v4 aa:bb:cc:dd:ee:ff 192.168.1.2 # Desktop
v6 0000000000000000000000000000 00000000  aaaa:bbbb:cccc:dddd:1:2:3:4 # Desktop
v6 00-00-00-00-00-00-00-00-00-00-00-00-00-00 00000000  aaaa:bbbb:cccc:dddd:1:2:3:4 # Desktop 2
subnet 255.255.255.0
gateway 192.168.1.1
broadcast 192.168.1.255
dns_server 192.168.1.1 aaaa:bbbb:cccc:dddd::1
dns_search example.net.invalid
ntp_server 192.168.1.1 aaaa:bbbb:cccc:dddd::1
dynamic_range 192.168.1.100 192.168.1.254
dynamic_v6

# Supports only ipv4.  Maybe it's wifi?
interface eth1
v4 aa:bb:cc:dd:ee:ff 192.168.2.2 # Desktop
subnet 255.255.255.0
gateway 192.168.2.1
broadcast 192.168.2.255
dns_server 192.168.2.1
dns_search example.net.invalid
ntp_server 192.168.2.1
dynamic_range 192.168.2.100 192.168.2.254
```

## Remarks on IPv4 and IPv6 differences

IPv6 is very different than IPv4.

IPv6 supports two different methods (stateful, stateless) of automatic
IP address allocation.  IPv4 only supports stateful allocation.

Stateful allocation is the familiar DHCPv4 approach, where a centralized
server has authority for IP address allocation on a set of local network
segments.  Hosts make queries to this server and are provided with IP
addresses by the server, which records the mappings (state) between hosts
(identified by MAC or IAID/DUIDs) and IP addresses.

DHCPv6 can support this model, but it also allows for stateless
autoconfiguration, where address assignment is not explicitly tracked.

IPv6 stateless address allocation eliminates the need for a centralized
server to keep track of mappings between hosts and IP addresses.
Instead, information about the network (prefix, dns/ntp servers)
is provided to hosts by routers on the local network segment (link).
Hosts use this information to calculate a probabalistically unique IP
address, which is then verified for uniqueness by interrogating the
network (using IPv6 Neighbor Discovery/Duplicate Address Detection).

This is fine for situations where it does not matter what addresses
are assigned to clients; these addresses may even intentionally change
over time (see Privacy Extensions and Temporary Addresses).  However,
if it is necessary for mappings to remain constant, or to vary but be
coordinated with DNS entries, stateful address assignment is necessary.

Stateful assignment still requires router advertisements to be provided.
Many types of necessary information (notably the default gateway) are
provided via router advertisements and not by DHCPv6.

ndhs is designed to support the stateful autoconfiguration model.
It provides all functionality required for stateful autoconfiguration to
fully function for hosts.  It should be run only on IPv4/IPv6 routers,
and only on interfaces on the router for which the router performs
routing duties.

## Downloads

* [GitLab](https://gitlab.com/niklata/ndhs)
* [Codeberg](https://codeberg.org/niklata/ndhs)
* [BitBucket](https://bitbucket.com/niklata/ndhs)
* [GitHub](https://github.com/niklata/ndhs)

## Portability

ndhs could be ported to non-Linux systems, but will require new code to
replace the netlink mechanism used in Linux.  Some security hardening
features (`SO_LOCK_FILTER`) would need to be disabled, too.

