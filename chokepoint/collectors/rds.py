"""RDS collector: database instances.

Read-only calls only: describe_db_instances. RDS instances are
crown-jewel candidates (the production database) and the target of
the P1 credential chain: a bucket holding database credentials is
only dangerous because a database exists to use them against.
"""

from __future__ import annotations

from .records import DBInstance, tags_to_dict


def collect_db_instances(rds_client) -> list[DBInstance]:
    paginator = rds_client.get_paginator("describe_db_instances")
    dbs = []
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            dbs.append(
                DBInstance(
                    identifier=db["DBInstanceIdentifier"],
                    arn=db.get("DBInstanceArn", ""),
                    engine=db.get("Engine", ""),
                    publicly_accessible=bool(db.get("PubliclyAccessible", False)),
                    vpc_security_group_ids=tuple(
                        g.get("VpcSecurityGroupId")
                        for g in db.get("VpcSecurityGroups", [])
                    ),
                    tags=tags_to_dict(db.get("TagList")),
                )
            )
    return dbs
