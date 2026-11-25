DROP INDEX IF EXISTS forwards_node_public_port_uniq;
DROP INDEX IF EXISTS forwards_node_idx;
ALTER TABLE forwards DROP COLUMN IF EXISTS node;

DROP INDEX IF EXISTS hosts_node_consumer_ipv6_uniq;
DROP INDEX IF EXISTS hosts_node_consumer_ipv4_uniq;
DROP INDEX IF EXISTS hosts_node_listen_port_uniq;
DROP INDEX IF EXISTS hosts_node_tunnel_ipv6_uniq;
DROP INDEX IF EXISTS hosts_node_tunnel_ipv4_uniq;

-- Restoring the global constraints fails if the fleet already holds symmetric
-- duplicates (the whole point of the forward migration). That is intentional:
-- a rollback must be explicit about collapsing the addressing first.
ALTER TABLE hosts ADD CONSTRAINT hosts_tunnel_ipv4_key UNIQUE (tunnel_ipv4);
ALTER TABLE hosts ADD CONSTRAINT hosts_tunnel_ipv6_key UNIQUE (tunnel_ipv6);
ALTER TABLE hosts ADD CONSTRAINT hosts_listen_port_key UNIQUE (listen_port);
ALTER TABLE hosts ADD CONSTRAINT hosts_consumer_tunnel_ipv4_key UNIQUE (consumer_tunnel_ipv4);
ALTER TABLE hosts ADD CONSTRAINT hosts_consumer_tunnel_ipv6_key UNIQUE (consumer_tunnel_ipv6);