"""EC2 collector: instances, security groups, route tables.

Read-only calls only: describe_instances, describe_security_groups,
describe_route_tables. Everything a P1 path needs to decide whether
an instance is reachable from the Internet:

* a public IP address,
* a security group ingress rule open to 0.0.0.0/0 (or ::/0),
* a route to an internet gateway (0.0.0.0/0 -> igw-...) in the
  subnet's route table.
"""

from __future__ import annotations

from .records import (
    EC2Instance,
    Route,
    RouteTable,
    SecurityGroup,
    SGRule,
    tags_to_dict,
)


def _parse_sg_rules(ip_permissions) -> tuple[SGRule, ...]:
    rules = []
    for perm in ip_permissions or []:
        protocol = str(perm.get("IpProtocol", "-1"))
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        for ip_range in perm.get("IpRanges", []) or []:
            cidr = ip_range.get("CidrIp")
            if cidr:
                rules.append(SGRule(cidr, protocol, from_port, to_port))
        for ip_range in perm.get("Ipv6Ranges", []) or []:
            cidr = ip_range.get("CidrIpv6")
            if cidr:
                rules.append(SGRule(cidr, protocol, from_port, to_port))
    return tuple(rules)


def collect_security_groups(ec2_client) -> list[SecurityGroup]:
    paginator = ec2_client.get_paginator("describe_security_groups")
    groups = []
    for page in paginator.paginate():
        for g in page.get("SecurityGroups", []):
            groups.append(
                SecurityGroup(
                    id=g["GroupId"],
                    vpc_id=g.get("VpcId", ""),
                    ingress=_parse_sg_rules(g.get("IpPermissions")),
                    egress=_parse_sg_rules(g.get("IpPermissionsEgress")),
                )
            )
    return groups


def collect_route_tables(ec2_client) -> list[RouteTable]:
    paginator = ec2_client.get_paginator("describe_route_tables")
    tables = []
    for page in paginator.paginate():
        for t in page.get("RouteTables", []):
            subnet_ids = tuple(
                a.get("SubnetId")
                for a in t.get("Associations", [])
                if a.get("SubnetId")
            )
            routes = tuple(
                Route(
                    destination=r.get("DestinationCidrBlock")
                    or r.get("DestinationIpv6CidrBlock", ""),
                    target=r.get("GatewayId")
                    or r.get("NatGatewayId")
                    or r.get("TransitGatewayId", ""),
                )
                for r in t.get("Routes", [])
            )
            tables.append(
                RouteTable(id=t["RouteTableId"], vpc_id=t.get("VpcId", ""),
                           subnet_ids=subnet_ids, routes=routes)
            )
    return tables


def collect_instances(ec2_client) -> list[EC2Instance]:
    paginator = ec2_client.get_paginator("describe_instances")
    instances = []
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                profile = inst.get("IamInstanceProfile") or {}
                instances.append(
                    EC2Instance(
                        id=inst["InstanceId"],
                        arn=inst.get("InstanceArn", ""),
                        state=inst.get("State", {}).get("Name", ""),
                        public_ip=inst.get("PublicIpAddress"),
                        private_ip=inst.get("PrivateIpAddress"),
                        subnet_id=inst.get("SubnetId", ""),
                        vpc_id=inst.get("VpcId", ""),
                        security_group_ids=tuple(
                            g.get("GroupId") for g in inst.get("SecurityGroups", [])
                        ),
                        instance_profile_arn=profile.get("Arn"),
                        tags=tags_to_dict(inst.get("Tags")),
                    )
                )
    return instances


def collect_ec2(ec2_client) -> tuple[list[EC2Instance], list[SecurityGroup], list[RouteTable]]:
    """Collect all EC2 data Phase 1 needs, in one call."""
    return (
        collect_instances(ec2_client),
        collect_security_groups(ec2_client),
        collect_route_tables(ec2_client),
    )
