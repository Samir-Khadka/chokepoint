# Chokepoint — Phase 4

**Attack-path fixing instead of vulnerability lists.**

Phases 1–4 are done. Phase 1 built the foundation: a read-only
AWS collector, a Postgres-first graph, and path finding for the two
launch patterns. Phase 3 ranks the fixes: it answers *which five
fixes remove the most real attack paths to what matters?* Phase 4
generates the fix: a template turns the top-ranked fix into a
Terraform change plus a review-ready PR body — validated by
re-running path finding before anything is emitted. Opening a real
PR against a repo is the next step, not this build.

Full product plan: the Chokepoint Plan document (November 2026) — the
13-page plan behind this build.

## What Phase 3 does

- **Enumerate candidate fixes** — every edge on at least one
  attack path (cut that edge) and every non-entry, non-crown-jewel
  node on at least one path (remove that node and its incident
  edges). The Internet and crown jewels are never candidates.
- **Score by paths removed** — measured, not estimated: the path
  search is re-run with the candidate applied and the paths that
  disappear are counted. Only proven-confidence edges are scored.
- **Rank the Top 5** — by paths removed (descending), with
  path-graph betweenness centrality (Brandes, directed, over the
  subgraph induced by the attack paths) as the tiebreak, then
  candidate id for a fully deterministic order.
- **Minimum disconnecting set** — greedy set cover: repeatedly
  pick the fix removing the most still-uncovered paths until every
  path is disconnected. Reported as "N fixes disconnect all M
  paths". Greedy is an approximation of a minimum cut, not exact,
  and it is labelled as such.
- **Plain-language fixes** — each candidate carries a title, an
  explanation, the evidence behind it (which policy statement,
  rule, or attachment), and a "what could break" note. The
  blast-radius note is a heuristic from the graph evidence only
  and says so: a human must review it before anything changes.
  A fix here is a graph-level removal, **not** a validated
  Terraform change — that is Phase 4.

## What Phase 4 does

- **Terraform state parser** (`chokepoint/terraform/`) — parses
  `.tfstate` JSON (resources, addresses, attributes) and maps
  resource addresses to graph node ids, plus a minimal `.tf`
  config reader that locates a resource block by address and does
  brace-matched surgery on it. It is a fixture-scoped reader, not
  a general HCL parser: no variables, modules, `for_each`, or
  computed values.
- **Demo Terraform fixture** (`chokepoint/demo/terraform/`) —
  `main.tf` + `terraform.tfstate` that mirror the demo account
  1:1 (public EC2 web server, web-role and its policies,
  admin-role, customer-data + backups buckets, prod-db RDS,
  security groups). 39 resources; every demo resource maps to
  its graph node id. The fixture's only credential is the
  placeholder string `placeholder-credential-not-real`.
- **Template-based fix generation** (`chokepoint/fixes/`,
  **no LLM anywhere**) — six templates, chosen by candidate kind
  and edge kind: detach a role from an instance, narrow (or
  remove) an over-broad policy statement, close public
  security-group ingress, make a workload private, remove a
  trust-policy principal, make an S3 bucket private, remove a
  stored credential object. Each template takes a ranked fix +
  the fixture and returns the full modified `.tf`, a unified
  diff, and the resource addresses changed. A template's graph
  effect is declared from the change itself — narrowing a policy
  removes only the edges that statement granted — not copied
  from the ranking, so the PR body reports measured numbers and
  says so when they differ from the ranked estimate (fix #2
  measures 4 → 2 paths; the ranked estimate was 3 removed).
- **Mandatory before/after validation** — the fix is applied to
  a copy of the in-memory graph using the same exclusion
  mechanism as the ranking module, path finding is re-run, and
  the fix is emitted only if it removes paths **and** introduces
  none. A fix that does not reduce paths is refused with an
  error and **no output files are written**. The record reports
  before/after counts and exactly which paths disappeared.
- **PR body generator** — markdown with a title, a
  plain-language summary, the fix with its diff, before/after
  path counts and the removed paths, what could break, a
  validation statement, a re-scan verification plan, and a
  "review before merging" note. Chokepoint never merges its own
  PRs.
- **CLI** — `chokepoint fix --demo [--fix N] [--out-dir DIR]`
  picks the Nth ranked fix (default 1) and writes `main.tf`,
  `pr-body.md`, and `validation.json` into `fixes/<fix-id>/`
  (or `--out-dir`). The generator only writes files; it never
  applies changes to real infrastructure, and there is no
  `--apply` flag in this phase.

**Limits (Phase 4, honest):** templates assume the fixture's
known structure (resource naming, `jsonencode` policies, one
policy per statement list); general-purpose HCL editing is future
work. Fixes are generated for the demo fixture only — a real
account has no `.tf` to edit yet, so `fix` requires `--demo`.
Opening a real PR against a repo is the next step, not this
build. Some ranked fixes have no template (a role whose policies
are already scoped; a bucket that is already private) — those
are refused cleanly, with no files written, rather than
generating a no-op change.

## What Phase 1 does (foundation, unchanged)

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

The ranked fixes:

```bash
.venv/bin/python -m chokepoint top-fixes --demo
.venv/bin/python -m chokepoint top-fixes --demo --output json
.venv/bin/python -m chokepoint top-fixes --demo --top 3
```

Expected output: the top fix is **"Detach role/web-role from
ec2:i-web00001"** (removes 3 of 4 paths, protects `rds:prod-db`,
betweenness 11.0), and the minimum disconnecting set is **2 fixes**
disconnecting all 4 paths (detach the role, then make
`s3://customer-data` private).

Generate the Terraform fix for the top-ranked fix, with its PR
body and validation record:

```bash
.venv/bin/python -m chokepoint fix --demo
.venv/bin/python -m chokepoint fix --demo --fix 2 --out-dir /tmp/fix2
```

Expected output: fix #1 takes the demo from **4 paths to 1**
(3 removed, 0 new) and writes `main.tf`, `pr-body.md`, and
`validation.json` into `fixes/edge-ec2-i-web00001-iam-role-web-role-has_role/`.
The generated diff is one line — the `iam_instance_profile`
removed from `aws_instance.web`. Fix #2 narrows the over-broad
policy statement to `s3://assets` and takes the demo from 4
paths to 2, with a note that the ranked estimate was 3 removed.
Nothing is applied to real infrastructure.

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

126 tests, all passing (1 skipped: the live-Postgres round-trip,
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
- Ranking: top fix removes 3 paths and involves web-role, greedy
  set disconnects all 4 paths with 2 fixes, betweenness matches a
  hand computation (web-role node 9.0, ec2→web-role edge 11.0), a
  decoy-only candidate scores 0 and never ranks, ranking is
  deterministic, CLI text and JSON output shapes.
- Phase 4: the state parser maps every demo resource in the
  fixture tfstate; the config reader locates blocks and does
  brace-matched surgery; each template produces a modified `.tf`
  that still parses (python-hcl2, a dev dependency) with the
  expected change, pinned by golden files in `tests/golden/`
  (one per template kind — a template change is a deliberate
  golden update); validation takes the demo from 4 paths to 1
  for the top fix, refuses a no-op fix and a fix that would add
  paths, and reports measured vs ranked counts; CLI end-to-end
  in demo mode for fix #1 and fix #2 (files written, PR body
  contains the before/after numbers); generation is
  deterministic.
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
                patterns.py (P1/P2 DFS, choke-point count; Phase 3
                  exclusion params to simulate a fix)
  ranking/      candidates.py (edge/node fix enumeration, titles,
                  explanations, evidence, what-could-break)
                centrality.py (Brandes node + edge betweenness on
                  the path subgraph)
                ranking.py (score by paths removed, rank Top 5,
                  greedy disconnecting set)
  demo/         inventory.json + loader
                terraform/ (main.tf + terraform.tfstate mirroring
                  inventory.json 1:1)
  terraform/    state.py   (tfstate JSON parser, address -> node id)
                config.py  (minimal .tf block reader + span surgery)
  fixes/        _hcl.py    (jsonencode/heredoc policy helpers)
                templates.py (template selection + application)
                validation.py (before/after re-run, refuse rule)
                generate.py (pipeline: template -> validate -> diff)
                prbody.py  (review-ready PR body markdown)
  cli.py        scan / list-paths / top-fixes / fix
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
- No LLM anywhere. Fix generation is template-based (Phase 4);
  an LLM is a later phase, if ever.
- The fix generator only writes files. It never applies a change
  to real infrastructure, and there is no `--apply` flag.

## Explicitly NOT in this phase

Per the plan, deferred — do not mistake absence for oversight:

- **P3 instance-metadata chains** (IMDSv1 / SSRF → temporary
  credentials) — fast follow after P1/P2 accuracy is proven.
- **Opening a real PR against a repo** — Phase 4 generates the
  `.tf` change, the PR body, and the validation record; pushing
  them to a repo as a pull request is the next step.
- **General-purpose HCL editing** — the templates are
  fixture-scoped (known resource naming, `jsonencode` policies);
  variables, modules, `for_each`, and computed values are future
  work.
- **Fix generation for real accounts** — `fix` is demo-fixture
  only in this phase; a real account has no `.tf` to edit yet.
- Web UI, GitHub App.
- **Multi-cloud, Kubernetes, CI/CD and code graphs, SaaS.**
- ALB / load-balancer entry points (NetworkEntry nodes are ready
  for them).
