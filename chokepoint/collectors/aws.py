"""Read-only AWS access guard.

Chokepoint scans with read-only credentials only (plan Section 7
safety rules). As defence in depth, every boto3 client used by a
collector is wrapped so that any call whose name does not start with
a read-only prefix raises immediately — a collector can never
accidentally (or via a bad fixture) perform a write, even if the
credentials it was handed would allow it.

Read-only prefixes: ``describe_``, ``list_``, ``get_``, ``head_``.
These cover every AWS read API the Phase 1 collectors need.
"""

from __future__ import annotations

READ_ONLY_PREFIXES = ("describe_", "list_", "get_", "head_")


class ReadOnlyViolationError(RuntimeError):
    """Raised when code tries a non-read API call through the guard."""


class ReadOnlyClient:
    """Thin wrapper around a boto3 client that only allows read calls."""

    def __init__(self, client, service_name: str) -> None:
        self._client = client
        self.service_name = service_name
        # Expose the underlying client's exception classes so
        # collectors can catch e.g. NoSuchBucketPolicy normally.
        self.exceptions = client.exceptions

    def __getattr__(self, name: str):
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def guarded(*args, **kwargs):
            if not name.startswith(READ_ONLY_PREFIXES):
                raise ReadOnlyViolationError(
                    f"refusing non-read AWS call: {self.service_name}.{name} "
                    "(Chokepoint scans are read-only)"
                )
            return attr(*args, **kwargs)

        return guarded

    @property
    def meta(self):
        return self._client.meta


def make_clients(session, region: str) -> dict[str, ReadOnlyClient]:
    """Build read-only wrapped clients for the services Phase 1 uses."""
    out = {}
    for service in ("ec2", "s3", "iam", "rds", "sts"):
        out[service] = ReadOnlyClient(session.client(service, region_name=region), service)
    return out
