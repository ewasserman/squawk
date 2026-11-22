"""The squawk relay server, which holds sealed messages for services on
different networks. The protocol is described in docs/plan/relay.md."""

from squawk.relay.limits import Rate, RelayLimits
from squawk.relay.server import RelayServer

__all__ = ["Rate", "RelayLimits", "RelayServer"]
