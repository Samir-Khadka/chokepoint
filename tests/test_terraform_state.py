"""Tests for the Terraform state parser (Phase 4).

The fixture tfstate must map 1:1 to the demo account: every
resource in the fixture maps to a graph node id where one exists,
and every graph node in the demo has a state resource behind it.
"""

import json

import pytest

from chokepoint.demo import demo_terraform_dir, load_demo_terraform
from chokepoint.terraform import (
    StateParseError,
    address_to_node_id,
    load_state,
    node_id_to_address,
    parse_state,
)


@pytest.fixture(scope="module")
def demo_state():
    _, state_data = load_demo_terraform()
    return parse_state(state_data)


def test_fixture_state_parses(demo_state):
    assert len(demo_state.resources) == 39
    assert demo_state.terraform_version == "1.5.0"


def test_load_state_from_disk():
    state = load_state(demo_terraform_dir() / "terraform.tfstate")
    assert len(state.resources) == 39


def test_every_demo_resource_maps(demo_state):
    """Every resource that should be a graph node maps to one."""
    expected = {
        "aws_instance.web": "ec2:i-web00001",
        "aws_instance.worker": "ec2:i-wrk00001",
        "aws_instance.bastion": "ec2:i-bas00001",
        "aws_iam_role.web_role": "iam-role:web-role",
        "aws_iam_role.admin_role": "iam-role:admin-role",
        "aws_iam_role.worker_role": "iam-role:worker-role",
        "aws_iam_role.bastion_role": "iam-role:bastion-role",
        "aws_iam_role.orphan_role": "iam-role:orphan-role",
        "aws_s3_bucket.backups": "s3:backups",
        "aws_s3_bucket.assets": "s3:assets",
        "aws_s3_bucket.customer_data": "s3:customer-data",
        "aws_s3_bucket.logs": "s3:logs",
        "aws_db_instance.prod_db": "rds:prod-db",
    }
    for address, node_id in expected.items():
        resource = demo_state.by_address(address)
        assert resource is not None, address
        assert address_to_node_id(resource) == node_id
        assert node_id_to_address(demo_state, node_id) == address


def test_non_node_resources_map_to_none(demo_state):
    """Security groups, policies, profiles are not graph nodes."""
    for address in (
        "aws_security_group.web",
        "aws_iam_role_policy.web_policy",
        "aws_iam_policy.database_connect",
        "aws_iam_instance_profile.web_profile",
        "aws_vpc.demo",
        "aws_s3_bucket_policy.customer_data",
        "aws_s3_object.db_creds",
    ):
        resource = demo_state.by_address(address)
        assert resource is not None, address
        assert address_to_node_id(resource) is None


def test_unknown_node_id_has_no_address(demo_state):
    assert node_id_to_address(demo_state, "ec2:i-nope") is None


def test_state_version_rejected():
    with pytest.raises(StateParseError):
        parse_state({"version": 2, "resources": []})


def test_state_without_resources_rejected():
    with pytest.raises(StateParseError):
        parse_state({"version": 4})


def test_resource_without_instances_skipped():
    state = parse_state({
        "version": 4,
        "resources": [
            {"mode": "managed", "type": "aws_s3_bucket", "name": "empty",
             "instances": []},
            {"mode": "managed", "type": "aws_s3_bucket", "name": "real",
             "instances": [{"attributes": {"id": "real", "bucket": "real"}}]},
        ],
    })
    assert [r.address for r in state.resources] == ["aws_s3_bucket.real"]


def test_data_sources_skipped():
    state = parse_state({
        "version": 4,
        "resources": [
            {"mode": "data", "type": "aws_caller_identity", "name": "me",
             "instances": [{"attributes": {"account_id": "1"}}]},
        ],
    })
    assert state.resources == ()


def test_load_state_rejects_bad_json(tmp_path):
    bad = tmp_path / "bad.tfstate"
    bad.write_text("{not json")
    with pytest.raises(StateParseError):
        load_state(bad)


def test_fixture_state_is_valid_json():
    text = (demo_terraform_dir() / "terraform.tfstate").read_text()
    json.loads(text)  # raises if invalid
