-- Reverse of 0004: move addresses back into the legacy single-pair networks.
-- Symmetric: only rows currently inside the per-transport networks are moved.
UPDATE hosts SET
    tunnel_ipv4 = ('10.13.36.' || split_part(host(tunnel_ipv4), '.', 4))::inet,
    tunnel_ipv6 = ('fd00:36::' || regexp_replace(host(tunnel_ipv6), '^.*::', ''))::inet
WHERE tunnel_ipv4 << '10.66.66.0/24'::inet OR tunnel_ipv4 << '10.77.77.0/24'::inet;

UPDATE hosts SET
    consumer_tunnel_ipv4 = ('10.13.36.' || split_part(host(consumer_tunnel_ipv4), '.', 4))::inet,
    consumer_tunnel_ipv6 = ('fd00:36::' || regexp_replace(host(consumer_tunnel_ipv6), '^.*::', ''))::inet
WHERE consumer_tunnel_ipv4 IS NOT NULL
  AND (consumer_tunnel_ipv4 << '10.66.66.0/24'::inet OR consumer_tunnel_ipv4 << '10.77.77.0/24'::inet);