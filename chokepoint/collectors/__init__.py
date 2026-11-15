"""Top-level scan orchestration.

``scan_account`` runs every Phase 1 collector against read-only
wrapped boto3 clients and returns one :class:`Inventory`. It makes
no write calls and never touches credentials: it only reads.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from .aws import make_clients
from .ec2 import collect_ec2
from .iam import collect_roles, resolve_instance_profile_roles
from .rds import collect_db_instances
from .records import Inventory
from .s3 import collect_buckets


def scan_account(session, region: str) -> Inventory:
    """Collect the Phase 1 inventory for one account/region."""
    clients = make_clients(session, region)
    account_id = ""
    try:
        account_id = clients["sts"].get_caller_identity().get("Account", "")
    except Exception:
        account_id = ""
    instances, security_groups, route_tables = collect_ec2(clients["ec2"])
    roles = collect_roles(clients["iam"])
    # Resolve instance profiles to the roles they carry so the graph
    # builder can draw HAS_ROLE edges.
    profile_arns = [i.instance_profile_arn for i in instances if i.instance_profile_arn]
    profile_roles = resolve_instance_profile_roles(clients["iam"], profile_arns)
    instances = [
        replace(i, role_arn=profile_roles.get(i.instance_profile_arn or ""))
        if i.instance_profile_arn
        else i
        for i in instances
    ]
    return Inventory(
        account_id=account_id,
        region=region,
        collected_at=datetime.now(timezone.utc).isoformat(),
        instances=instances,
        security_groups=security_groups,
        route_tables=route_tables,
        buckets=collect_buckets(clients["s3"], account_id),
        roles=roles,
        db_instances=collect_db_instances(clients["rds"]),
    )
