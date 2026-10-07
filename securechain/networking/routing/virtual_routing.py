"""Virtual Routing Controller for simulated networks, testing, and un-elevated execution."""

import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional

from securechain.core.exceptions import RoutingError
from securechain.networking.routing.controller import RouteEntry, RouteSnapshot, RoutingController
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.networking.virtual_routing")


class VirtualRoutingController(RoutingController):
    """Virtual routing engine that implements longest-prefix matching, rollback, and verification."""

    def __init__(self, initial_routes: Optional[List[RouteEntry]] = None) -> None:
        self._routes: Dict[str, RouteEntry] = {}
        self._temporary_destinations: set[str] = set()

        # Seed with realistic baseline host routes if none provided
        if initial_routes:
            for r in initial_routes:
                self._routes[r.destination] = r
        else:
            default_entry = RouteEntry(
                destination="0.0.0.0/0",
                gateway="192.168.1.1",
                interface="Ethernet0",
                metric=25,
                is_temporary=False,
            )
            local_subnet = RouteEntry(
                destination="192.168.1.0/24",
                gateway="0.0.0.0",
                interface="Ethernet0",
                metric=25,
                is_temporary=False,
            )
            self._routes[default_entry.destination] = default_entry
            self._routes[local_subnet.destination] = local_subnet

    def snapshot(self) -> RouteSnapshot:
        current_routes = list(self._routes.values())
        default_route = self._routes.get("0.0.0.0/0")
        return RouteSnapshot(
            timestamp=datetime.now(timezone.utc),
            routes=current_routes,
            default_gateway=default_route.gateway if default_route else None,
            default_interface=default_route.interface if default_route else None,
        )

    def get_routes(self) -> List[RouteEntry]:
        return list(self._routes.values())

    def add_route(self, destination: str, gateway: str, interface: str, metric: int = 10) -> bool:
        try:
            # Validate CIDR format
            ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise RoutingError(f"Invalid route destination CIDR '{destination}': {exc}") from exc

        route = RouteEntry(
            destination=destination,
            gateway=gateway,
            interface=interface,
            metric=metric,
            is_temporary=True,
        )
        self._routes[destination] = route
        self._temporary_destinations.add(destination)
        logger.info(f"Added route: {destination} -> {gateway} via {interface} (metric={metric})")
        return True

    def delete_route(self, destination: str, gateway: Optional[str] = None) -> bool:
        if destination in self._routes:
            del self._routes[destination]
            self._temporary_destinations.discard(destination)
            logger.info(f"Deleted route: {destination}")
            return True
        logger.warning(f"Attempted to delete nonexistent route: {destination}")
        return False

    def resolve_next_hop(self, target_ip: str) -> Optional[RouteEntry]:
        """Resolve next hop using longest-prefix matching with metric tie-breaking."""
        target = ipaddress.ip_address(target_ip)
        matched_routes: List[RouteEntry] = []

        for route in self._routes.values():
            net = route.network()
            if target in net:
                matched_routes.append(route)

        if not matched_routes:
            return None

        # Sort by prefix length descending (longest prefix match), then metric ascending
        matched_routes.sort(
            key=lambda r: (r.network().prefixlen, -r.metric),
            reverse=True,
        )
        return matched_routes[0]

    def verify_route(self, destination: str, expected_gateway: str) -> bool:
        # If destination specifies an explicit CIDR prefix, verify exact route presence
        if "/" in destination:
            if destination in self._routes:
                return self._routes[destination].gateway == expected_gateway
            return False

        # If destination is a raw host IP address, resolve next-hop
        resolved = self.resolve_next_hop(destination)
        return resolved is not None and resolved.gateway == expected_gateway

    def detect_unexpected_changes(self, snapshot: RouteSnapshot) -> List[RouteEntry]:
        snapshot_destinations = {r.destination: r for r in snapshot.routes}
        unexpected: List[RouteEntry] = []

        for dest, route in self._routes.items():
            if dest not in self._temporary_destinations:
                if dest not in snapshot_destinations:
                    unexpected.append(route)
                elif snapshot_destinations[dest].gateway != route.gateway:
                    unexpected.append(route)
        return unexpected

    def restore(self, snapshot: RouteSnapshot) -> bool:
        logger.info("Restoring routing table to snapshot state...")
        self._routes = {r.destination: r for r in snapshot.routes}
        self._temporary_destinations.clear()
        return True

    def cleanup_temporary_routes(self) -> int:
        removed_count = 0
        for dest in list(self._temporary_destinations):
            if dest in self._routes:
                del self._routes[dest]
                removed_count += 1
        self._temporary_destinations.clear()
        logger.info(f"Cleaned up {removed_count} temporary routes")
        return removed_count

    # Test hooks
    def inject_unauthorized_route(self, destination: str, gateway: str, interface: str) -> None:
        """Inject a rogue route to test unexpected route detection."""
        entry = RouteEntry(
            destination=destination,
            gateway=gateway,
            interface=interface,
            metric=1,
            is_temporary=False,  # Not marked as temporary by orchestrator
        )
        self._routes[destination] = entry
        logger.warning(f"Injected rogue route: {destination} -> {gateway}")
