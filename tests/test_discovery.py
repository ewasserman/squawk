"""Tests for squawk.discovery."""

import asyncio
import os
import re
import shutil
from collections.abc import Callable
from typing import Any

import pytest

from squawk.crypto import ed25519_public_key, ed25519_random_secret_key
from squawk.discovery import (
    Advertisement,
    DiscoveredPeer,
    Discovery,
    DnsSdBackend,
    MdnsBackend,
    RawService,
    ZeroconfBackend,
    default_backend,
    parse_dns_sd_txt,
    peer_from_service,
)
from squawk.encoding import key_id
from squawk.identity import fingerprint


def make_ad(name: str, port: int) -> Advertisement:
    pub = ed25519_public_key(ed25519_random_secret_key())
    return Advertisement(name=name, key_id=key_id(pub), fingerprint=fingerprint(pub), port=port)


class FakeNetwork:
    """A fake mDNS "network": every backend attached to it sees every other's adverts."""

    def __init__(self) -> None:
        self.backends: list[FakeBackend] = []
        self.services: dict[str, tuple[FakeBackend, RawService]] = {}

    def announce(self, owner: "FakeBackend", service: RawService) -> None:
        self.services[service.name] = (owner, service)
        for b in list(self.backends):
            if b.on_up is not None:
                b.on_up(service)

    def withdraw(self, owner: "FakeBackend") -> None:
        for name, (who, service) in list(self.services.items()):
            if who is not owner:
                continue
            del self.services[name]
            # A goodbye packet carries only the instance name.
            for b in list(self.backends):
                if b.on_down is not None:
                    b.on_down(RawService(name=service.name, host=service.host, port=0, txt={}))


class FakeBackend:
    def __init__(self, net: FakeNetwork) -> None:
        self.net = net
        self.on_up: Callable[[RawService], None] | None = None
        self.on_down: Callable[[RawService], None] | None = None

    async def publish(self, instance_name: str, port: int, txt: dict[str, str]) -> None:
        self.net.announce(
            self,
            RawService(
                name=instance_name,
                host=f"{instance_name}.local",
                port=port,
                addresses=["fe80::1", "192.168.1.5"],
                txt=txt,
            ),
        )

    async def browse(
        self, on_up: Callable[[RawService], None], on_down: Callable[[RawService], None]
    ) -> None:
        self.on_up = on_up
        self.on_down = on_down
        self.net.backends.append(self)
        for _owner, service in list(self.net.services.values()):
            on_up(service)

    def query(self) -> None:
        for _owner, service in list(self.net.services.values()):
            if self.on_up is not None:
                self.on_up(service)

    async def destroy(self) -> None:
        self.net.backends.remove(self)
        self.net.withdraw(self)


ad = make_ad("alice", 4100)
base = RawService(
    name="alice (abcd)",
    host="alice.local",
    port=4100,
    txt={"name": "alice", "id": ad.key_id, "fp": ad.fingerprint, "port": "4100"},
)


def with_txt(**changes: Any) -> RawService:
    return RawService(name=base.name, host=base.host, port=base.port, txt={**base.txt, **changes})


def test_peer_from_service_reads_name_key_fingerprint_and_port() -> None:
    service = RawService(
        name=base.name,
        host=base.host,
        port=base.port,
        addresses=["fe80::1", "10.0.0.2"],
        txt=base.txt,
    )
    assert peer_from_service(service, 42) == DiscoveredPeer(
        name="alice",
        key_id=ad.key_id,
        fingerprint=ad.fingerprint,
        host="alice.local",
        addresses=["10.0.0.2", "fe80::1"],
        port=4100,
        last_seen=42,
    )


def test_peer_from_service_accepts_txt_values_given_as_bytes() -> None:
    txt = {k: str(v).encode() for k, v in base.txt.items()}
    service = RawService(name=base.name, host=base.host, port=base.port, txt=txt)
    peer = peer_from_service(service, 0)
    assert peer is not None and peer.name == "alice"


def test_peer_from_service_rejects_bad_key_ids_and_ports() -> None:
    assert peer_from_service(with_txt(id="nope"), 0) is None
    assert peer_from_service(with_txt(port="99999"), 0) is None
    assert peer_from_service(with_txt(port="12.5"), 0) is None
    assert peer_from_service(RawService(name=base.name, host=base.host, port=1, txt={}), 0) is None


def test_peer_from_service_uses_the_srv_port_when_txt_has_none() -> None:
    txt = {k: v for k, v in base.txt.items() if k != "port"}
    peer = peer_from_service(RawService(name=base.name, host=base.host, port=4555, txt=txt), 0)
    assert peer is not None and peer.port == 4555


async def test_finds_other_services_ignores_itself_and_notices_when_one_leaves() -> None:
    net = FakeNetwork()
    a = Discovery(make_ad("alice", 4100), backend=FakeBackend(net))
    b_ad = make_ad("bob", 4200)
    b = Discovery(b_ad, backend=FakeBackend(net))
    downs: list[DiscoveredPeer] = []
    a.on("down", downs.append)

    await a.start()
    await b.start()

    assert [p.name for p in a.peers()] == ["bob"]
    assert [p.name for p in b.peers()] == ["alice"]
    found = a.peer(b_ad.key_id)
    assert found is not None and found.port == 4200

    await b.stop()
    assert a.peers() == []
    assert [p.key_id for p in downs] == [b_ad.key_id]
    await a.stop()


def test_uses_a_unique_instance_name_built_from_the_name_and_fingerprint() -> None:
    advert = make_ad("alice", 1)
    d = Discovery(advert, backend=FakeBackend(FakeNetwork()))
    assert d.instance_name() == f"alice ({advert.fingerprint.replace('-', '')[:8]})"


def test_parse_dns_sd_txt_splits_on_unescaped_spaces_and_keeps_escaped_ones() -> None:
    assert parse_dns_sd_txt(" name=Alice\\ Smith id=abc fp=12-34 port=4100") == {
        "name": "Alice Smith",
        "id": "abc",
        "fp": "12-34",
        "port": "4100",
    }


def test_default_backend_can_be_chosen_with_squawk_mdns() -> None:
    assert isinstance(default_backend({"SQUAWK_MDNS": "dns-sd"}), DnsSdBackend)
    assert isinstance(default_backend({"SQUAWK_MDNS": "zeroconf"}), ZeroconfBackend)
    assert isinstance(default_backend({"SQUAWK_MDNS": "bonjour"}), ZeroconfBackend)


# Real multicast DNS. Hosted CI runners often block multicast, so these run
# only on a developer machine (or when SQUAWK_TEST_MDNS=1).
real_mdns = pytest.mark.skipif(
    bool(os.environ.get("CI")) and os.environ.get("SQUAWK_TEST_MDNS") != "1",
    reason="real mDNS is skipped when CI is set (set SQUAWK_TEST_MDNS=1 to run it)",
)


async def find_each_other(
    make_a: Callable[[], MdnsBackend], make_b: Callable[[], MdnsBackend] | None = None
) -> None:
    a_ad = make_ad(f"sq-test-a-{os.getpid()}", 47001)
    b_ad = make_ad(f"sq-test-b-{os.getpid()}", 47002)
    a = Discovery(a_ad, backend=make_a())
    b = Discovery(b_ad, backend=(make_b or make_a)())
    loop = asyncio.get_running_loop()
    a_sees_b: asyncio.Future[DiscoveredPeer] = loop.create_future()
    b_sees_a: asyncio.Future[DiscoveredPeer] = loop.create_future()

    def watch(
        future: "asyncio.Future[DiscoveredPeer]", key: str
    ) -> Callable[[DiscoveredPeer], None]:
        def listener(peer: DiscoveredPeer) -> None:
            if peer.key_id == key and not future.done():
                future.set_result(peer)

        return listener

    a.on("up", watch(a_sees_b, b_ad.key_id))
    b.on("up", watch(b_sees_a, a_ad.key_id))
    try:
        await a.start()
        await b.start()

        async def refresh() -> None:
            while True:
                await asyncio.sleep(1)
                a.refresh()
                b.refresh()

        refresher = asyncio.ensure_future(refresh())
        try:
            seen_b, seen_a = await asyncio.wait_for(asyncio.gather(a_sees_b, b_sees_a), 15)
        finally:
            refresher.cancel()
        assert seen_b.port == 47002
        assert seen_a.port == 47001
        assert seen_b.fingerprint == b_ad.fingerprint
        assert re.fullmatch(r"sq-test-b-\d+", seen_b.name)
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.mdns
@real_mdns
async def test_two_services_find_each_other_over_real_mdns() -> None:
    await find_each_other(default_backend)


@pytest.mark.mdns
@real_mdns
async def test_two_services_find_each_other_with_zeroconf() -> None:
    await find_each_other(ZeroconfBackend)


@pytest.mark.mdns
@real_mdns
@pytest.mark.skipif(shutil.which("dns-sd") is None, reason="needs the dns-sd command (macOS)")
async def test_a_dns_sd_service_and_a_zeroconf_service_find_each_other() -> None:
    await find_each_other(DnsSdBackend, ZeroconfBackend)
