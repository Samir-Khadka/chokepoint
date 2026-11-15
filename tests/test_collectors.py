"""Tests for the AWS collectors, using stubbed boto3 responses.

No real AWS calls are ever made: every client is a botocore
Stubber. This also covers the read-only guard in collectors/aws.py.
"""

import boto3
import pytest
from botocore.stub import Stubber

from chokepoint.collectors import scan_account
from chokepoint.collectors.aws import ReadOnlyClient, ReadOnlyViolationError
from chokepoint.collectors.ec2 import collect_ec2
from chokepoint.collectors.iam import collect_roles
from chokepoint.collectors.rds import collect_db_instances
from chokepoint.collectors.s3 import collect_buckets


def _client(service):
    return boto3.client(
        service,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


# --- EC2 ---------------------------------------------------------------------

def test_collect_ec2_parses_instances_sgs_and_routes():
    client = _client("ec2")
    stub = Stubber(client)
    stub.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1",
                            "State": {"Name": "running"},
                            "PublicIpAddress": "54.0.0.1",
                            "PrivateIpAddress": "10.0.1.5",
                            "SubnetId": "subnet-1",
                            "VpcId": "vpc-1",
                            "SecurityGroups": [{"GroupId": "sg-1"}],
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123456789012:instance-profile/p1"
                            },
                            "Tags": [{"Key": "Name", "Value": "web"}],
                        }
                    ]
                }
            ]
        },
    )
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "VpcId": "vpc-1",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        },
    )
    stub.add_response(
        "describe_route_tables",
        {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-1",
                    "VpcId": "vpc-1",
                    "Associations": [{"SubnetId": "subnet-1"}],
                    "Routes": [
                        {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                        {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"},
                    ],
                }
            ]
        },
    )
    stub.activate()
    instances, groups, tables = collect_ec2(client)
    stub.assert_no_pending_responses()

    assert len(instances) == 1
    inst = instances[0]
    assert inst.id == "i-1"
    assert inst.public_ip == "54.0.0.1"
    assert inst.tags == {"Name": "web"}
    assert inst.instance_profile_arn.endswith("instance-profile/p1")
    assert groups[0].ingress[0].cidr == "0.0.0.0/0"
    assert groups[0].ingress[0].from_port == 443
    assert tables[0].routes[1].target == "igw-1"


# --- S3 ----------------------------------------------------------------------

def test_collect_buckets_public_policy_and_missing_policy():
    client = _client("s3")
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "pub"}, {"Name": "priv"}]})
    # pub: public bucket policy
    stub.add_response(
        "get_bucket_policy",
        {"Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}'},
        {"Bucket": "pub"},
    )
    stub.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": {}},
        {"Bucket": "pub"},
    )
    stub.add_response("get_bucket_acl", {"Grants": []}, {"Bucket": "pub"})
    stub.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404)
    # priv: no bucket policy at all
    stub.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", http_status_code=404)
    stub.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": {"BlockPublicPolicy": True}},
        {"Bucket": "priv"},
    )
    stub.add_response("get_bucket_acl", {"Grants": []}, {"Bucket": "priv"})
    stub.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404)
    stub.activate()
    buckets = collect_buckets(client)
    stub.assert_no_pending_responses()

    assert [b.name for b in buckets] == ["pub", "priv"]
    assert buckets[0].policy["Statement"][0]["Principal"] == "*"
    assert buckets[1].policy is None
    assert buckets[1].public_access_block["BlockPublicPolicy"] is True


def test_collect_buckets_public_acl():
    client = _client("s3")
    stub = Stubber(client)
    stub.add_response("list_buckets", {"Buckets": [{"Name": "acl-pub"}]})
    stub.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", http_status_code=404)
    stub.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": {}},
        {"Bucket": "acl-pub"},
    )
    stub.add_response(
        "get_bucket_acl",
        {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ]
        },
        {"Bucket": "acl-pub"},
    )
    stub.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404)
    stub.activate()
    buckets = collect_buckets(client)
    assert buckets[0].acl_public is True


# --- IAM ---------------------------------------------------------------------

def test_collect_roles_resolves_attached_and_inline_policies():
    client = _client("iam")
    stub = Stubber(client)
    stub.add_response(
        "list_roles",
        {
            "Roles": [
                {
                    "RoleName": "web-role",
                    "Arn": "arn:aws:iam::123456789012:role/web-role",
                    "Path": "/",
                    "RoleId": "AROA1234567890ABCDEF",
                    "CreateDate": "2026-01-01T00:00:00Z",
                }
            ]
        },
    )
    stub.add_response(
        "get_role",
        {
            "Role": {
                "RoleName": "web-role",
                "Arn": "arn:aws:iam::123456789012:role/web-role",
                "Path": "/",
                "RoleId": "AROA1234567890ABCDEF",
                "CreateDate": "2026-01-01T00:00:00Z",
                "AssumeRolePolicyDocument": (
                    "%7B%22Statement%22%3A%20%5B%7B%22Effect%22%3A%20%22Allow"
                    "%22%2C%20%22Principal%22%3A%20%7B%22Service%22%3A%20%22"
                    "ec2.amazonaws.com%22%7D%2C%20%22Action%22%3A%20%22sts"
                    "%3AAssumeRole%22%7D%5D%7D"
                ),
            }
        },
        {"RoleName": "web-role"},
    )
    stub.add_response(
        "list_attached_role_policies",
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "ReadOnlyAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                }
            ]
        },
        {"RoleName": "web-role"},
    )
    stub.add_response(
        "get_policy",
        {
            "Policy": {
                "PolicyName": "ReadOnlyAccess",
                "PolicyId": "ANPA1234567890ABCDEF",
                "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "Path": "/",
                "DefaultVersionId": "v1",
                "AttachmentCount": 1,
                "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True,
                "CreateDate": "2026-01-01T00:00:00Z",
                "UpdateDate": "2026-01-01T00:00:00Z",
            }
        },
        {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )
    stub.add_response(
        "get_policy_version",
        {
            "PolicyVersion": {
                "Document": (
                    '{"Statement": [{"Effect": "Allow", "Action": "s3:Get*", '
                    '"Resource": "*"}]}'
                ),
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        },
        {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "VersionId": "v1"},
    )
    stub.add_response(
        "list_role_policies", {"PolicyNames": ["inline-p"]}, {"RoleName": "web-role"}
    )
    stub.add_response(
        "get_role_policy",
        {
            "RoleName": "web-role",
            "PolicyName": "inline-p",
            "PolicyDocument": (
                '{"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", '
                '"Resource": "*"}]}'
            ),
        },
        {"RoleName": "web-role", "PolicyName": "inline-p"},
    )
    stub.activate()
    roles = collect_roles(client)
    stub.assert_no_pending_responses()

    assert len(roles) == 1
    role = roles[0]
    assert role.name == "web-role"
    assert role.trust_policy["Statement"][0]["Principal"] == {
        "Service": "ec2.amazonaws.com"
    }
    names = [name for name, _ in role.policies]
    assert names == ["attached:ReadOnlyAccess", "inline:inline-p"]


# --- RDS ---------------------------------------------------------------------

def test_collect_db_instances():
    client = _client("rds")
    stub = Stubber(client)
    stub.add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-db",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                    "Engine": "postgres",
                    "PubliclyAccessible": False,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db"}],
                    "TagList": [{"Key": "Environment", "Value": "production"}],
                }
            ]
        },
    )
    stub.activate()
    dbs = collect_db_instances(client)
    assert len(dbs) == 1
    assert dbs[0].identifier == "prod-db"
    assert dbs[0].tags == {"Environment": "production"}
    assert dbs[0].publicly_accessible is False


# --- Read-only guard ----------------------------------------------------------

def test_read_only_client_blocks_writes():
    raw = _client("s3")
    wrapped = ReadOnlyClient(raw, "s3")
    with pytest.raises(ReadOnlyViolationError):
        wrapped.create_bucket(Bucket="nope")
    with pytest.raises(ReadOnlyViolationError):
        wrapped.put_object(Bucket="x", Key="y", Body=b"z")


def test_read_only_client_passes_reads():
    raw = _client("s3")
    stub = Stubber(raw)
    stub.add_response("list_buckets", {"Buckets": []})
    stub.activate()
    wrapped = ReadOnlyClient(raw, "s3")
    assert wrapped.list_buckets() == {"Buckets": []}


# --- scan_account orchestration (stubbed end to end) --------------------------

class _FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, service, region_name=None):
        return self._clients[service]


def test_scan_account_resolves_instance_profile_to_role():
    ec2 = _client("ec2")
    ec2_stub = Stubber(ec2)
    ec2_stub.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1",
                            "State": {"Name": "running"},
                            "SubnetId": "subnet-1",
                            "VpcId": "vpc-1",
                            "SecurityGroups": [],
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123456789012:instance-profile/p1"
                            },
                        }
                    ]
                }
            ]
        },
    )
    ec2_stub.add_response("describe_security_groups", {"SecurityGroups": []})
    ec2_stub.add_response("describe_route_tables", {"RouteTables": []})
    ec2_stub.activate()

    iam = _client("iam")
    iam_stub = Stubber(iam)
    iam_stub.add_response("list_roles", {"Roles": []})
    iam_stub.add_response(
        "get_instance_profile",
        {
            "InstanceProfile": {
                "InstanceProfileName": "p1",
                "InstanceProfileId": "AIPA1234567890ABCDEF",
                "Arn": "arn:aws:iam::123456789012:instance-profile/p1",
                "Path": "/",
                "Roles": [
                    {
                        "RoleName": "web-role",
                        "Arn": "arn:aws:iam::123456789012:role/web-role",
                        "Path": "/",
                        "RoleId": "AROA1234567890ABCDEF",
                        "CreateDate": "2026-01-01T00:00:00Z",
                    }
                ],
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        },
        {"InstanceProfileName": "p1"},
    )
    iam_stub.activate()

    s3 = _client("s3")
    s3_stub = Stubber(s3)
    s3_stub.add_response("list_buckets", {"Buckets": []})
    s3_stub.activate()

    rds = _client("rds")
    rds_stub = Stubber(rds)
    rds_stub.add_response("describe_db_instances", {"DBInstances": []})
    rds_stub.activate()

    sts = _client("sts")
    sts_stub = Stubber(sts)
    sts_stub.add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "AID123",
        },
    )
    sts_stub.activate()

    session = _FakeSession(
        {"ec2": ec2, "iam": iam, "s3": s3, "rds": rds, "sts": sts}
    )
    inv = scan_account(session, "us-east-1")
    assert inv.account_id == "123456789012"
    assert inv.instances[0].role_arn == "arn:aws:iam::123456789012:role/web-role"
    for stub in (ec2_stub, iam_stub, s3_stub, rds_stub, sts_stub):
        stub.assert_no_pending_responses()
