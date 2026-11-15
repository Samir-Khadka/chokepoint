# Root conftest: makes the local ``chokepoint`` package importable
# when pytest runs from the project root, and shared demo fixtures
# for the Phase 3/4 suites (graph + ranking + Terraform fixture).

import pytest

from chokepoint.demo import load_demo_inventory, load_demo_terraform
from chokepoint.graph.builder import build_graph
from chokepoint.graph.memory import InMemoryGraphStore
from chokepoint.graph.model import Node
from chokepoint.paths.crown_jewels import suggest_crown_jewels
from chokepoint.paths.patterns import find_paths
from chokepoint.ranking import rank_fixes
from chokepoint.terraform import parse_state


@pytest.fixture()
def demo_graph():
    """The demo account as a graph store + its 4 attack paths."""
    inventory = load_demo_inventory()
    store = InMemoryGraphStore()
    build_graph(inventory, store)
    for node_id in suggest_crown_jewels(inventory):
        node = store.get_node(node_id)
        if node is not None:
            store.add_node(
                Node(
                    id=node.id,
                    kind=node.kind,
                    label=node.label,
                    attributes=node.attributes,
                    crown_jewel=True,
                )
            )
    paths = find_paths(store)
    return {"inventory": inventory, "store": store, "paths": paths}


@pytest.fixture()
def demo_ranking(demo_graph):
    """All ranked fixes for the demo account (top 15)."""
    return rank_fixes(demo_graph["store"], demo_graph["paths"], top=15)


@pytest.fixture()
def demo_fixture():
    """The demo Terraform fixture: (main.tf text, parsed state)."""
    main_tf, state_data = load_demo_terraform()
    return main_tf, parse_state(state_data)
