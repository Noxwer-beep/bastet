"""Subnet maths without reaching for a calculator.

Every analyst eventually gets asked "is 10.20.30.40 in that range" at 03:00.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class Subnet:
    cidr: str
    version: int
    network: str
    netmask: str
    wildcard: str
    broadcast: str | None
    first_host: str | None
    last_host: str | None
    total_addresses: int
    usable_hosts: int
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "version": self.version,
            "network": self.network,
            "netmask": self.netmask,
            "wildcard": self.wildcard,
            "broadcast": self.broadcast,
            "first_host": self.first_host,
            "last_host": self.last_host,
            "total_addresses": self.total_addresses,
            "usable_hosts": self.usable_hosts,
            "is_private": self.is_private,
            "is_loopback": self.is_loopback,
            "is_link_local": self.is_link_local,
            "is_multicast": self.is_multicast,
        }


def parse(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Accept 10.0.0.0/24, 10.0.0.5/24, or a bare address (assumed /32)."""
    text = value.strip()
    if "/" not in text:
        text += "/32" if ":" not in text else "/128"
    return ipaddress.ip_network(text, strict=False)


def subnet(value: str) -> Subnet:
    net = parse(value)
    total = net.num_addresses
    if net.version == 4:
        usable = total - 2 if total > 2 else total
        first = str(net.network_address + 1) if total > 2 else str(net.network_address)
        last = str(net.broadcast_address - 1) if total > 2 else str(net.broadcast_address)
        broadcast = str(net.broadcast_address)
    else:
        usable = total
        first = str(net.network_address)
        last = str(net.broadcast_address)
        broadcast = None
    return Subnet(
        cidr=str(net),
        version=net.version,
        network=str(net.network_address),
        netmask=str(net.netmask),
        wildcard=str(net.hostmask),
        broadcast=broadcast,
        first_host=first,
        last_host=last,
        total_addresses=total,
        usable_hosts=usable,
        is_private=net.is_private,
        is_loopback=net.is_loopback,
        is_link_local=net.is_link_local,
        is_multicast=net.is_multicast,
    )


def contains(cidr: str, address: str) -> bool:
    """True when `address` sits inside `cidr`."""
    net = parse(cidr)
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return False
    return ip in net


def overlap(a: str, b: str) -> bool:
    return parse(a).overlaps(parse(b))


def summarise(cidr: str) -> str:
    """One line for a ticket: how many, and is it internal."""
    s = subnet(cidr)
    scope = "private" if s.is_private else "public"
    if s.version == 4:
        return f"{s.cidr} — {s.usable_hosts} usable hosts, {scope}, {s.first_host}–{s.last_host}"
    return f"{s.cidr} — {s.total_addresses} addresses, {scope}"
