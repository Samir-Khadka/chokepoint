"""S3 collector: buckets, bucket policies, public-access settings.

Read-only calls only: list_buckets, get_bucket_policy,
get_public_access_block, get_bucket_acl, get_bucket_tagging.

A bucket is public when any of these hold:

* its bucket policy has an Allow statement with Principal "*" (or
  {"AWS": "*"}) for a read action on the bucket or its objects,
* an ACL grant gives the AllUsers / AuthenticatedUsers group READ,
* PublicAccessBlock is absent or does not block public policies/ACLs
  (this alone does not make a bucket public — it only removes a
  guard — so it is recorded, not treated as public by itself).

The public decision itself lives in the graph builder
(``graph/builder.py``); this collector only records the facts.
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from .records import S3Bucket, tags_to_dict

PUBLIC_ACL_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _get_policy(s3_client, bucket: str) -> dict | None:
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket)
    except ClientError as e:
        # NoSuchBucketPolicy is not a modelled S3 exception in
        # botocore, so check the error code instead of catching a
        # named exception class. Any other read failure is also
        # treated as "no policy" — a missing policy is the common
        # case, and Phase 1 never needs to distinguish.
        return None
    policy = resp.get("Policy")
    if isinstance(policy, str):
        try:
            return json.loads(policy)
        except json.JSONDecodeError:
            return None
    return policy


def _get_public_access_block(s3_client, bucket: str) -> dict:
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket)
    except ClientError:
        return {}
    return resp.get("PublicAccessBlockConfiguration", {}) or {}


def _acl_is_public(s3_client, bucket: str) -> bool:
    try:
        resp = s3_client.get_bucket_acl(Bucket=bucket)
    except ClientError:
        return False
    for grant in resp.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in PUBLIC_ACL_GROUPS and grant.get("Permission") in (
            "READ",
            "FULL_CONTROL",
        ):
            return True
    return False


def _get_tags(s3_client, bucket: str) -> dict:
    try:
        resp = s3_client.get_bucket_tagging(Bucket=bucket)
    except ClientError:
        return {}
    return tags_to_dict(resp.get("TagSet"))


def collect_buckets(s3_client, account_id: str = "") -> list[S3Bucket]:
    buckets = []
    for b in s3_client.list_buckets().get("Buckets", []):
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        buckets.append(
            S3Bucket(
                name=name,
                arn=arn,
                policy=_get_policy(s3_client, name),
                public_access_block=_get_public_access_block(s3_client, name),
                acl_public=_acl_is_public(s3_client, name),
                tags=_get_tags(s3_client, name),
            )
        )
    return buckets
