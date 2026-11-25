-- Tunnel addresses and transport ports live in each gateway node's own space:
-- berg and glacier may both hand out 10.66.66.6 or port 6666, because a peer
-- dials them separately and the reply route is chosen by destination gateway.
-- The global uniqueness introduced in 0001 was an artifact of the single-node
-- MVP and made symmetric multi-node addressing impossible.
--
-- Name stays globally unique: it is the human handle and appears in DNS/UFW
-- comments, so "mc-home" must mean exactly one host in the whole fleet.
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_tunnel_ipv4_key;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_tunnel_ipv6_key;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_listen_port_key;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_consumer_tunnel_ipv4_key;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_consumer_tunnel_ipv6_key;

CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_tunnel_ipv4_uniq ON hosts (node, tunnel_ipv4);
CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_tunnel_ipv6_uniq ON hosts (node, tunnel_ipv6);
CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_listen_port_uniq ON hosts (node, listen_port);
CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_consumer_ipv4_uniq
    ON hosts (node, consumer_tunnel_ipv4) WHERE consumer_tunnel_ipv4 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_consumer_ipv6_uniq
    ON hosts (node, consumer_tunnel_ipv6) WHERE consumer_tunnel_ipv6 IS NOT NULL;

-- A public port is bound on one gateway, so it is unique per node: two hosts on
-- the same node with the same public port would silently race in DNAT ("first
-- rule wins") and steal each other's traffic. Denormalising `node` onto the
-- forward is what makes that constraint expressible; the reconciler already
-- works per node, so the column is also the natural query key.
ALTER TABLE forwards ADD COLUMN node text NOT NULL DEFAULT 'test';
UPDATE forwards f SET node = h.node FROM hosts h WHERE h.id = f.host_id;
CREATE INDEX IF NOT EXISTS forwards_node_idx ON forwards (node);
CREATE UNIQUE INDEX IF NOT EXISTS forwards_node_public_port_uniq
    ON forwards (node, public_port, proto);