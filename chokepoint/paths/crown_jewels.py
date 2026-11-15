"""Crown-jewel tagging (plan Section 4: "Tag" stage).

The user marks what matters. Phase 1 suggests tags from inventory
metadata and accepts explicit tags; the CLI also takes
``--crown-jewel <node-id>``. A node id is returned, not a node —
the caller marks it on the store (``add_node`` with
``crown_jewel=True`` merges, never losing the tag).
"""

from __future__ import annotations

from ..collectors.records import Inventory


def suggest_crown_jewels(inventory: Inventory) -> list[str]:
    """Node ids that look like crown jewels, from tags alone.

    Rules (all opt-in via tags — nothing is guessed from a name):
    * any resource tagged ``crown-jewel=true``
    * an RDS instance tagged ``Environment=production``
    * an S3 bucket tagged ``sensitivity`` in
      ``customer-data`` / ``credentials`` / ``restricted``
    * an IAM role tagged ``admin=true`` (an admin identity)
    """
    jewels: list[str] = []
    for db in inventory.db_instances:
        tags = db.tags
        if tags.get("crown-jewel") == "true" or tags.get("Environment") == "production":
            jewels.append(f"rds:{db.identifier}")
    for bucket in inventory.buckets:
        tags = bucket.tags
        if tags.get("crown-jewel") == "true" or tags.get("sensitivity") in (
            "customer-data",
            "credentials",
            "restricted",
        ):
            jewels.append(f"s3:{bucket.name}")
    for role in inventory.roles:
        if role.tags.get("crown-jewel") == "true" or role.tags.get("admin") == "true":
            jewels.append(f"iam-role:{role.name}")
    return jewels
