# Chokepoint — Phase 1

**Attack-path fixing instead of vulnerability lists.**

Phase 1 builds the foundation the plan calls for: a read-only AWS
collector, a Postgres-first graph, and path finding for the two
launch patterns. It answers one question: *which routes exist from
the public Internet to what matters?* Fix generation (templates,
Terraform PRs) is Phase 4 — deliberately not here.

Full product plan: the Chokepoint Plan document (November 2026) — the
13-page plan behind this build.

## What Phase 1 does

- **Collect** — read-only boto3 collectors for EC2 instances,
  security groups, route tables, S3 buckets (+ policies, ACLs,
  public-access blocks), IAM roles (+ trust policies, attached and
  inline policies resolved to documents, permission boundaries),
  and RDS instances.
- **Model** — everything becomes a graph. Nodes: Internet,
  Workload, Identity, DataStore, Secret, NetworkEntry. Edges:
  `can_reach`, `has_role`, `can_assume`, `can_read`, `can_write`,
  `can_admin`, `contains_cred`. Every edge carries its evidence
  (which policy statement, rule, or attachment created it) and a
  confidence of `proven` or `unknown`. Unknown edges are labelled,
  never silently assumed.
- **Find paths** — two patterns only:
  - **P1 — public entry + role chain:** Internet → public EC2 →
    role → (assume-role)* → crown jewel.
  - **P2 — public storage:** Internet → public S3 bucket → crown
    jewel (the bucket itself, or credentials it holds).
- **Tag crown jewels** — from tags (`crown-jewel=true`,
  `Environment=production` RDS, `sensitivity=customer-data` S3,
  `admin=true` roles) or explicit `--crown-jewel <node-id>`.
- **Demo mode** — a bundled mock account runs end-to-end with zero
  credentials and prints the found paths with the choke point
  marked (the node the most paths pass through; full ranking is
  Phase 3).

## Setup

Requires Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .          # boto3 only
.venv/bin/pip install -e ".[postgres]"  # + psycopg, for the Postgres backend
.venv/bin/pip install -e ".[dev]"       # + pytest
```

## Demo run (no credentials needed)

```bash
.venv/bin/python -m chokepoint scan --demo
```

Expected output: 15 nodes, 30 edges, 2 crown jewels
(`rds:prod-db`, `s3:customer-data`), **4 attack paths** — three P1
and one P2 — with `role/web-role` as the top choke point (3 of 4
paths pass through it). Machine-readable output:

```bash
.venv/bin/python -m chokepoint list-paths --demo --output json
```

The demo account is hand-built so its paths are known exactly
(`chokepoint/demo/inventory.json`): a public EC2 whose
over-permissioned role can read a backups bucket holding the prod
DB credentials, plus an assumable admin role — and decoys that must
produce no path (a private worker, a bastion whose SG allows only
one office IP, a public-but-empty logs bucket, an orphan role with
broad permissions and no way in).

## Real scan (read-only)

```bash
.venv/bin/python -m chokepoint scan --region us-east-1 --profile my-readonly
```

Uses a least-privilege read-only role. As defence in depth, every
boto3 client is wrapped so any non-read API call
(`describe_*` / `list_*` / `get_*` / `head_*` only) raises
immediately — a collector can never perform a write, even if the
credentials would allow it. To store the graph in Postgres instead
of memory:

```bash
.venv/bin/python -m chokepoint scan --region us-east-1 \
    --postgres postgresql://user:pass@localhost/chokepoint
# or set CHOKEPOINT_DSN; schema in chokepoint/graph/schema.sql
```

## Tests

```bash
.venv/bin/python -m pytest
```

46 tests, all passing (1 skipped: the live-Postgres round-trip,
which needs `CHOKEPOINT_TEST_DSN` pointing at a test database —
no Postgres is installed in this environment). Coverage:

- IAM evaluator: wildcard matching, explicit Deny wins,
  permission boundaries, trust policies, and every
  unknown-confidence escape (`NotAction`, unsupported Conditions).
- Collectors: stubbed boto3 responses (botocore Stubber) — never a
  real AWS call — including URL-encoded policy documents, missing
  bucket policies, and public ACLs.
- Graph builder + path finding on the demo account: exactly the 4
  planted paths, zero invented paths, decoys in none of them,
  unknown edges never followed.
- CLI end-to-end in demo mode (text and JSON).

## Architecture

```
chokepoint/
  collectors/   records.py (Inventory dataclasses)
                aws.py     (read-only client guard)
                ec2.py s3.py iam.py rds.py  (one collector per service)
                __init__.py (scan_account orchestration)
  graph/        model.py   (Node/Edge, kinds, confidence)
                store.py   (GraphStore protocol)
                memory.py  (in-memory backend: tests + demo)
                postgres.py (Postgres backend, psycopg)
                schema.sql (DDL + recursive-CTE reachability view)
                iam_eval.py (narrow policy evaluator + role_can)
                builder.py (Inventory -> graph edges)
  paths/        crown_jewels.py (tag suggestions)
                patterns.py (P1/P2 DFS, choke-point count)
  demo/         inventory.json + loader
  cli.py        scan / list-paths
```

Design choices worth knowing:

- **Postgres first, in-memory second.** The path engine only talks
  to the `GraphStore` protocol, so backends are interchangeable.
  Reachability in SQL is a recursive CTE (`schema.sql`,
  `cp_reachable_crown_jewels` view); the Python engine enumerates
  the actual paths.
- **IAM semantics is the product.** The evaluator covers identity
  policies, resource policies, trust policies and permission
  boundaries. Anything outside that subset (`NotAction`,
  `NotResource`, Conditions other than a bare `StringEquals` on
  `aws:PrincipalArn`) yields `unknown` — and unknown edges are
  never followed by the path finder.
- **Credentials in buckets are declared, not discovered.** Phase 1
  does not read object contents. A bucket's `credential` field
  records that it holds credentials for a target (populated by the
  demo loader; a secrets-scanner integration fills it for real
  accounts later).
- **NetworkEntry nodes exist in the model but are unused in Phase
  1.** The security-group rule is cited as evidence on the
  `can_reach` edge directly, matching the plan's Figure 1 chain.
  ALB-as-entry-point will use NetworkEntry nodes when it lands.

## Safety

- Read-only scanning credentials, always. No write API is ever
  called; the guard raises on any attempt.
- No active exploitation, no credential use, no lateral movement.
  Analysis only.
- Demo mode uses no credentials and no network.
- No LLM anywhere in this phase. Fix generation is Phase 4.

## Explicitly NOT in this phase

Per the plan, deferred — do not mistake absence for oversight:

- **P3 instance-metadata chains** (IMDSv1 / SSRF → temporary
  credentials) — fast follow after P1/P2 accuracy is proven.
- **Fix generation and Terraform PRs** (Phase 4), choke-point
  ranking / Top-5 list (Phase 3), web UI, GitHub App.
- **Terraform-state parser** — listed in the plan's Phase 1, but
  out of this build's scope; the fix generator (Phase 4) is what
  needs to write back into Terraform, so the parser lands with it.
- **Multi-cloud, Kubernetes, CI/CD and code graphs, SaaS.**
- ALB / load-balancer entry points (NetworkEntry nodes are ready
  for them).
