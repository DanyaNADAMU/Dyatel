-- Multi-node support: each daemon reconciles only its own hosts.
-- 'test' = staging core node, 'berg' = production proxer node.
ALTER TABLE hosts ADD COLUMN node text NOT NULL DEFAULT 'test';
CREATE INDEX hosts_node_idx ON hosts (node);