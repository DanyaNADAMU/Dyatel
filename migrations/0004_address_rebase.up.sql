-- Rebase existing tunnel addresses onto the per-transport networks introduced
-- in v2.3.0 (WG 10.66.66.0/24 + fd66:66::/64, AWG 10.77.77.0/24 + fd77:77::/64).
--
-- Why a migration and not a re-create: hosts carry BYOK peer keys, PSKs and
-- gateway keypairs. Dropping them would force every owner to regenerate keys
-- and every peer to re-register, for a change that only moves the host part
-- into a new network. The host part (last octet / last hextet) is preserved,
-- so a peer keeps a memorable number (…66.6 stays …::6).
--
-- Hosts already inside the new networks are untouched, which makes the
-- migration safe to run on a fleet where part of it was created after the
-- upgrade.
UPDATE hosts SET
    tunnel_ipv4 = (
        CASE transport
            WHEN 'amneziawg' THEN '10.77.77.'
            ELSE '10.66.66.'
        END || split_part(host(tunnel_ipv4), '.', 4))::inet,
    tunnel_ipv6 = (
        CASE transport
            WHEN 'amneziawg' THEN 'fd77:77::'
            ELSE 'fd66:66::'
        END || regexp_replace(host(tunnel_ipv6), '^.*::', ''))::inet
WHERE NOT (
    (transport <> 'amneziawg' AND tunnel_ipv4 << '10.66.66.0/24'::inet)
    OR (transport = 'amneziawg' AND tunnel_ipv4 << '10.77.77.0/24'::inet)
);

UPDATE hosts SET
    consumer_tunnel_ipv4 = (
        CASE transport
            WHEN 'amneziawg' THEN '10.77.77.'
            ELSE '10.66.66.'
        END || split_part(host(consumer_tunnel_ipv4), '.', 4))::inet,
    consumer_tunnel_ipv6 = (
        CASE transport
            WHEN 'amneziawg' THEN 'fd77:77::'
            ELSE 'fd66:66::'
        END || regexp_replace(host(consumer_tunnel_ipv6), '^.*::', ''))::inet
WHERE consumer_tunnel_ipv4 IS NOT NULL AND NOT (
    (transport <> 'amneziawg' AND consumer_tunnel_ipv4 << '10.66.66.0/24'::inet)
    OR (transport = 'amneziawg' AND consumer_tunnel_ipv4 << '10.77.77.0/24'::inet)
);