-- Chokepoint Phase 1 — Postgres graph schema (plan Section 6).
--
-- Postgres-first: no dedicated graph database until profiling shows
-- reachability queries are the bottleneck. Run with:
--   psql "$CHOKEPOINT_DSN" -f chokepoint/graph/schema.sql
--
-- Nodes: internet | workload | identity | datastore | secret |
--        network_entry
-- Edges: can_reach | has_role | can_assume | can_read | can_write |
--        can_admin | contains_cred
-- Every edge carries its evidence and a confidence of proven|unknown.

CREATE TABLE IF NOT EXISTS cp_nodes (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    label       TEXT NOT NULL,
    attributes  JSONB NOT NULL DEFAULT '{}'::jsonb,
    crown_jewel BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS cp_edges (
    source       TEXT NOT NULL REFERENCES cp_nodes (id) ON DELETE CASCADE,
    target       TEXT NOT NULL REFERENCES cp_nodes (id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    evidence_ref TEXT NOT NULL DEFAULT '',
    confidence   TEXT NOT NULL DEFAULT 'proven'
                 CHECK (confidence IN ('proven', 'unknown')),
    collected_at TIMESTAMPTZ,
    PRIMARY KEY (source, target, kind)
);

CREATE INDEX IF NOT EXISTS cp_edges_source_idx ON cp_edges (source);
CREATE INDEX IF NOT EXISTS cp_edges_target_idx ON cp_edges (target);
CREATE INDEX IF NOT EXISTS cp_edges_kind_idx ON cp_edges (kind);
CREATE INDEX IF NOT EXISTS cp_nodes_crown_jewel_idx ON cp_nodes (crown_jewel)
    WHERE crown_jewel;

-- Reachability from the Internet to every crown jewel, following
-- proven edges only. Depth-capped at 8 hops with cycle handling
-- (the path array stops a node from repeating).
--
--   SELECT * FROM cp_reachable_crown_jewels();
--
-- The Python path engine (chokepoint/paths) enumerates the actual
-- paths over the GraphStore interface; this view is the SQL-side
-- check that the same reachability holds in the database.

CREATE OR REPLACE VIEW cp_reachable_crown_jewels AS
WITH RECURSIVE reach (node_id, path, depth) AS (
    SELECT 'internet'::TEXT, ARRAY['internet'::TEXT], 0
    UNION ALL
    SELECT e.target, r.path || e.target, r.depth + 1
    FROM reach r
    JOIN cp_edges e ON e.source = r.node_id
    WHERE e.confidence = 'proven'
      AND r.depth < 8
      AND NOT (e.target = ANY (r.path))
)
SELECT DISTINCT n.id AS crown_jewel_id, n.kind, n.label
FROM reach r
JOIN cp_nodes n ON n.id = r.node_id
WHERE n.crown_jewel = TRUE
  AND r.depth > 0;
