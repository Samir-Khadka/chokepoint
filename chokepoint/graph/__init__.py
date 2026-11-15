"""Graph package: model, stores, builder, IAM evaluator."""

from .builder import build_graph
from .iam_eval import EvalResult, policy_allows, role_can, trust_allows_assume
from .memory import InMemoryGraphStore
from .model import Confidence, Edge, EdgeKind, Node, NodeKind
from .store import GraphStore

__all__ = [
    "build_graph",
    "policy_allows",
    "role_can",
    "trust_allows_assume",
    "EvalResult",
    "InMemoryGraphStore",
    "GraphStore",
    "Node",
    "Edge",
    "NodeKind",
    "EdgeKind",
    "Confidence",
]
