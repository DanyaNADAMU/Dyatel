import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n } from "./i18n";
import type { DNSRecord, Host, Me } from "./types";

// The host list is the whole panel: one card per host with its role badge
// (proxer = owner, client = consumer), forwards + DNS table, and the rendered
// configs. RFC §4: no fan-out, exactly one owner and one consumer.
export default function Hosts({ me }: { me: Me }) {
  const { t } = useI18n();
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const [creating, setCreating] = useState(false);

  if (hosts.isPending) return <p className="opacity-60">{t.loadingHosts}</p>;
  if (hosts.isError) return <p className="text-red-600">{String(hosts.error.message)}</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium">{t.hostsTitle}</h2>
        <button
          className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 text-sm font-medium hover:opacity-90"
          onClick={() => setCreating(true)}
        >
          {t.addHost}
        </button>
      </div>
      {hosts.data.length === 0 && <p className="opacity-60 text-sm">{t.noHosts}</p>}
      {hosts.data.map((h) => (
        <HostCard key={h.id} host={h} me={me} />
      ))}
      {creating && <CreateHost isAdmin={me.is_admin} onClose={() => setCreating(false)} />}
    </div>
  );
}

function role(me: Me, h: Host): "proxer" | "client" | "admin" {
  if (h.owner_id === me.id) return "proxer";
  if (h.consumer_id === me.id) return "client";
  return "admin";
}

function Badge({ r }: { r: "proxer" | "client" | "admin" }) {
  const { t } = useI18n();
  const cls =
    r === "proxer"
      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200"
      : r === "client"
        ? "bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-200"
        : "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  const text = r === "proxer" ? t.roleProxer : r === "client" ? t.roleClient : t.roleAdmin;
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>{text}</span>;
}

function stateDot(state: string) {
  // Reconciled states are green; anything else (pending, suspended) is amber.
  return state === "active" ? "bg-emerald-500" : "bg-amber-500";
}

function HostCard({ host, me }: { host: Host; me: Me }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [showProxer, setShowProxer] = useState(false);
  const [showClient, setShowClient] = useState(false);
  const [editing, setEditing] = useState(false);
  const r = role(me, host);
  const canManage = r !== "client";
  const invalidate = () => qc.invalidateQueries({ queryKey: ["hosts"] });

  const del = useMutation({
    mutationFn: () => api.deleteHost(host.id),
    onSuccess: invalidate,
  });
  const setState = useMutation({
    mutationFn: (state: string) => api.setState(host.id, state),
    onSuccess: invalidate,
  });

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 rounded-full ${stateDot(host.state)}`} />
            <span className="font-medium">{host.name}</span>
            <Badge r={r} />
          </div>
          <p className="text-xs opacity-60 mt-1 font-mono">
            {host.node} · {host.transport} · {host.listen_port} · {host.tunnel_ipv4} ·{" "}
            {host.tunnel_ipv6}
          </p>
        </div>
        {canManage && (
          <div className="flex flex-wrap gap-2 text-sm">
            <button
              className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
              onClick={() => setEditing(true)}
            >
              {t.edit}
            </button>
            {host.state === "active" ? (
              <button
                className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                onClick={() => setState.mutate("suspended")}
              >
                {t.suspend}
              </button>
            ) : (
              <button
                className="rounded-lg border border-emerald-400 text-emerald-700 dark:text-emerald-300 px-3 py-1.5 hover:bg-emerald-50 dark:hover:bg-emerald-950"
                onClick={() => setState.mutate("active")}
              >
                {t.activate}
              </button>
            )}
            <button
              className="rounded-lg border border-red-300 text-red-700 dark:text-red-300 px-3 py-1.5 hover:bg-red-50 dark:hover:bg-red-950"
              onClick={() => {
                if (confirm(`${t.confirmDeleteHost} ${host.name}?`)) del.mutate();
              }}
            >
              {t.del}
            </button>
          </div>
        )}
      </div>

      <Forwards hostId={host.id} canCreate={canManage} />

      {(r === "client" || r === "admin") && !host.consumer_wg_public_key && (
        <ConsumerKeyForm host={host} />
      )}

      <div className="flex flex-wrap gap-2 text-sm">
        {canManage && (
          <button
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
            onClick={() => setShowProxer((v) => !v)}
          >
            {showProxer ? t.hideProxerCfg : t.showProxerCfg}
          </button>
        )}
        {(r === "client" || canManage) && (
          <button
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
            onClick={() => setShowClient((v) => !v)}
          >
            {showClient ? t.hideClientCfg : t.showClientCfg}
          </button>
        )}
      </div>
      {showProxer && (
        <ConfigBlock
          cacheKey={["config", "proxer", host.id]}
          load={() => api.proxerConfig(host.id)}
          label={t.roleProxer}
        />
      )}
      {showClient && (
        <ConfigBlock
          cacheKey={["config", "client", host.id]}
          load={() => api.clientConfig(host.id)}
          label={t.roleClient}
        />
      )}
      {r === "proxer" && <Onboarding host={host} side="proxer" />}
      {r === "client" && <Onboarding host={host} side="client" />}
      {(del.isError || setState.isError) && (
        <p className="text-xs text-red-600">{String((del.error ?? setState.error)?.message)}</p>
      )}
      {editing && <EditHost host={host} onClose={() => setEditing(false)} />}
    </div>
  );
}

function ConsumerKeyForm({ host }: { host: Host }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [pub, setPub] = useState("");
  const reg = useMutation({
    mutationFn: () => api.setConsumerKey(host.id, pub.trim()),
    onSuccess: () => {
      setPub("");
      return qc.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  return (
    <form
      className="rounded-lg border border-sky-200 dark:border-sky-900 bg-sky-50/50 dark:bg-sky-950/20 p-3 space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (pub.trim().length === 44) reg.mutate();
      }}
    >
      <p className="text-xs font-medium">{t.clientKeyTitle}</p>
      <p className="text-xs opacity-70">{t.clientKeyHint}</p>
      <div className="flex flex-wrap gap-2">
        <input
          className="flex-1 min-w-56 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5 text-xs font-mono"
          placeholder={t.pubKeyPlaceholder}
          value={pub}
          onChange={(e) => setPub(e.target.value)}
        />
        <button
          type="submit"
          className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3 py-1.5 text-xs font-medium disabled:opacity-50"
          disabled={reg.isPending || pub.trim().length !== 44}
        >
          {t.registerKeyBtn}
        </button>
      </div>
      {reg.isError && <p className="text-xs text-red-600">{String(reg.error.message)}</p>}
    </form>
  );
}

function ConfigBlock({
  cacheKey,
  load,
  label,
}: {
  cacheKey: string[];
  load: () => Promise<string>;
  label: string;
}) {
  const { t } = useI18n();
  const q = useQuery({ queryKey: cacheKey, queryFn: load, staleTime: 0 });
  return (
    <div className="space-y-2">
      <p className="text-xs opacity-60">
        {t.renderedConfig} — {label}
      </p>
      {q.isPending && <p className="text-xs opacity-60">{t.rendering}</p>}
      {q.isError && <p className="text-xs text-red-600">{String(q.error.message)}</p>}
      {q.data && (
        <div className="relative">
          <button
            className="absolute right-2 top-2 text-xs rounded bg-zinc-800 text-zinc-200 px-2 py-1 hover:bg-zinc-700"
            onClick={() => void navigator.clipboard.writeText(q.data)}
          >
            {t.copy}
          </button>
          <pre className="code">{q.data}</pre>
        </div>
      )}
    </div>
  );
}

function Forwards({ hostId, canCreate }: { hostId: string; canCreate: boolean }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const fs = useQuery({
    queryKey: ["forwards", hostId],
    queryFn: () => api.forwards(hostId),
  });
  const dnsQ = useQuery({
    queryKey: ["host-dns", hostId],
    queryFn: () => api.hostDNS(hostId),
  });
  const del = useMutation({
    mutationFn: (fid: string) => api.deleteForward(hostId, fid),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forwards", hostId] });
      void qc.invalidateQueries({ queryKey: ["host-dns", hostId] });
    },
  });
  const delDNS = useMutation({
    mutationFn: (fid: string) => api.deleteForwardDNS(fid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["host-dns", hostId] }),
  });

  const dnsByFwd = new Map<string, DNSRecord>();
  for (const d of dnsQ.data ?? []) {
    dnsByFwd.set(d.forward_id, d);
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{t.forwardsTitle}</h3>
        {canCreate && <ForwardForm hostId={hostId} />}
      </div>
      {fs.isPending && <p className="text-xs opacity-60">…</p>}
      {fs.isError && <p className="text-xs text-red-600">{String(fs.error.message)}</p>}
      {fs.data && fs.data.length === 0 && (
        <p className="text-xs opacity-60">{t.noForwards}</p>
      )}
      <table className="w-full text-sm">
        <tbody>
          {fs.data?.map((f) => {
            const dns = dnsByFwd.get(f.id);
            return (
              <tr key={f.id} className="border-t border-zinc-100 dark:border-zinc-800">
                <td className="py-1.5 pr-4 font-mono text-xs">
                  :{f.public_port} → :{f.target_port} {f.proto}
                </td>
                <td className="py-1.5 pr-4">{f.label}</td>
                <td className="py-1.5 pr-4">
                  {dns ? (
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                      <button
                        type="button"
                        className="rounded bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 hover:opacity-80"
                        onClick={() =>
                          void navigator.clipboard.writeText(`${dns.name}:${f.public_port}`)
                        }
                        title={t.copy}
                      >
                        {dns.name}
                      </button>
                      {canCreate && (
                        <button
                          type="button"
                          className="text-red-600 hover:underline"
                          onClick={() => delDNS.mutate(f.id)}
                          title={t.dnsRemove}
                        >
                          ×
                        </button>
                      )}
                    </span>
                  ) : (
                    canCreate && <ForwardDNSForm hostId={hostId} forwardId={f.id} />
                  )}
                </td>
                {canCreate && (
                  <td className="py-1.5 text-right">
                    <button
                      className="text-xs text-red-600 hover:underline"
                      onClick={() => del.mutate(f.id)}
                    >
                      {t.deleteLower}
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ForwardDNSForm({ hostId, forwardId }: { hostId: string; forwardId: string }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const setDNS = useMutation({
    mutationFn: () => api.setForwardDNS(forwardId, name.trim()),
    onSuccess: () => {
      setOpen(false);
      setName("");
      return qc.invalidateQueries({ queryKey: ["host-dns", hostId] });
    },
  });

  if (!open) {
    return (
      <button
        type="button"
        className="text-xs rounded border border-zinc-300 dark:border-zinc-700 px-2 py-0.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
        onClick={() => setOpen(true)}
      >
        {t.dnsBind}
      </button>
    );
  }

  return (
    <form
      className="inline-flex items-center gap-1.5 text-xs"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) setDNS.mutate();
      }}
    >
      <input
        className="w-36 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-0.5 font-mono"
        placeholder={t.dnsPlaceholder}
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <button
        type="submit"
        className="rounded bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-2 py-0.5 font-medium"
        disabled={setDNS.isPending || !name.trim()}
      >
        {t.dnsSave}
      </button>
      <button type="button" className="underline opacity-60" onClick={() => setOpen(false)}>
        {t.cancel}
      </button>
      {setDNS.isError && <span className="text-red-600">{String(setDNS.error.message)}</span>}
    </form>
  );
}

function ForwardForm({ hostId }: { hostId: string }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [pub, setPub] = useState("");
  const [tgt, setTgt] = useState("");
  const [proto, setProto] = useState("tcp");
  const [label, setLabel] = useState("");

  const create = useMutation({
    mutationFn: () =>
      api.createForward(hostId, {
        public_port: Number(pub),
        target_port: Number(tgt),
        proto,
        label,
      }),
    onSuccess: () => {
      setOpen(false);
      setPub("");
      setTgt("");
      setLabel("");
      return qc.invalidateQueries({ queryKey: ["forwards", hostId] });
    },
  });

  if (!open)
    return (
      <button
        className="text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 px-2.5 py-1 hover:bg-zinc-100 dark:hover:bg-zinc-800"
        onClick={() => setOpen(true)}
      >
        {t.addForwardBtn}
      </button>
    );
  return (
    <form
      className="flex flex-wrap items-center gap-1.5 text-xs"
      onSubmit={(e) => {
        e.preventDefault();
        if (Number(pub) > 0 && Number(tgt) > 0) create.mutate();
      }}
    >
      <input
        className="w-20 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1"
        placeholder={t.pubPort}
        value={pub}
        onChange={(e) => setPub(e.target.value)}
      />
      <input
        className="w-20 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1"
        placeholder={t.tgtPort}
        value={tgt}
        onChange={(e) => setTgt(e.target.value)}
      />
      <select
        className="rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-1.5 py-1"
        value={proto}
        onChange={(e) => setProto(e.target.value)}
      >
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
      </select>
      <input
        className="w-24 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1"
        placeholder={t.label}
        value={label}
        onChange={(e) => setLabel(e.target.value)}
      />
      <button
        className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-2.5 py-1 font-medium"
        type="submit"
      >
        {t.add}
      </button>
      <button type="button" className="underline opacity-60" onClick={() => setOpen(false)}>
        {t.cancel}
      </button>
      {create.isError && <span className="text-red-600">{String(create.error.message)}</span>}
    </form>
  );
}

function CreateHost({ isAdmin, onClose }: { isAdmin: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [pub, setPub] = useState("");
  const [transport, setTransport] = useState("amneziawg");
  const [consumer, setConsumer] = useState("");
  const [query, setQuery] = useState("");
  const [keepalive, setKeepalive] = useState("");
  const [node, setNode] = useState("");
  const [pref4, setPref4] = useState("");
  const [pref6, setPref6] = useState("");
  const [prefPort, setPrefPort] = useState("");

  // Directory-backed invitation: operators pick a person, never a raw UUID.
  const users = useQuery({
    queryKey: ["users", query],
    queryFn: () => api.users(query),
  });

  const create = useMutation({
    mutationFn: () =>
      api.createHost({
        name,
        wg_public_key: pub,
        transport,
        consumer_id: consumer,
        ...(Number(keepalive) > 0 ? { keepalive: Number(keepalive) } : {}),
        ...(isAdmin && node.trim() ? { node: node.trim() } : {}),
        ...(pref4.trim() ? { preferred_ipv4: pref4.trim() } : {}),
        ...(pref6.trim() ? { preferred_ipv6: pref6.trim() } : {}),
        ...(Number(prefPort) > 0 ? { preferred_port: Number(prefPort) } : {}),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-6 z-50">
      <form
        className="rounded-xl bg-white dark:bg-zinc-900 p-6 w-full max-w-md space-y-4 max-h-[90vh] overflow-y-auto"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <h2 className="text-lg font-medium">{t.registerHostTitle}</h2>
        <p className="text-xs opacity-60">{t.byokNote}</p>
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          placeholder={t.namePlaceholder}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm font-mono"
          placeholder={t.pubKeyPlaceholder}
          value={pub}
          onChange={(e) => setPub(e.target.value)}
        />
        <select
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          value={transport}
          onChange={(e) => setTransport(e.target.value)}
        >
          <option value="amneziawg">amneziawg</option>
          <option value="wireguard">wireguard</option>
        </select>

        <div className="space-y-1">
          <input
            className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
            placeholder={t.searchUsers}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="max-h-40 overflow-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
            {users.isPending && <p className="p-2 text-xs opacity-60">…</p>}
            {users.data?.length === 0 && <p className="p-2 text-xs opacity-60">{t.noUsers}</p>}
            {users.data?.map((u) => (
              <button
                key={u.id}
                type="button"
                className={`block w-full text-left px-3 py-1.5 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800 ${
                  consumer === u.id ? "font-medium bg-zinc-100 dark:bg-zinc-800" : ""
                }`}
                onClick={() => setConsumer(u.id)}
              >
                {u.display_name}
                {u.is_admin && <span className="ml-2 text-xs opacity-50">{t.admin}</span>}
                {consumer === u.id && <span className="ml-2 text-xs">✓ {t.invited}</span>}
              </button>
            ))}
          </div>
        </div>

        <details className="text-xs">
          <summary className="cursor-pointer select-none opacity-70 hover:opacity-100">
            {t.advancedOpts}
          </summary>
          <div className="mt-2 space-y-2">
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5"
              placeholder={t.keepalivePlaceholder}
              value={keepalive}
              onChange={(e) => setKeepalive(e.target.value)}
            />
            {isAdmin && (
              <input
                className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5"
                placeholder={t.nodePlaceholder}
                value={node}
                onChange={(e) => setNode(e.target.value)}
              />
            )}
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5 font-mono"
              placeholder={t.prefV4Placeholder}
              value={pref4}
              onChange={(e) => setPref4(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5 font-mono"
              placeholder={t.prefV6Placeholder}
              value={pref6}
              onChange={(e) => setPref6(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-1.5 font-mono"
              placeholder={t.prefPortPlaceholder}
              value={prefPort}
              onChange={(e) => setPrefPort(e.target.value)}
            />
          </div>
        </details>

        {create.isError && <p className="text-xs text-red-600">{String(create.error.message)}</p>}
        <div className="flex justify-end gap-2 text-sm">
          <button
            type="button"
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3.5 py-2"
            onClick={onClose}
          >
            {t.cancel}
          </button>
          <button
            type="submit"
            className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 font-medium disabled:opacity-50"
            disabled={!name || !consumer}
          >
            {t.create}
          </button>
        </div>
      </form>
    </div>
  );
}

function EditHost({ host, onClose }: { host: Host; onClose: () => void }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [endpoint, setEndpoint] = useState(host.endpoint ?? "");
  const [keepalive, setKeepalive] = useState(String(host.keepalive));
  const [consumer, setConsumer] = useState(host.consumer_id);
  const [query, setQuery] = useState("");

  const users = useQuery({
    queryKey: ["users", query],
    queryFn: () => api.users(query),
  });

  const save = useMutation({
    mutationFn: () =>
      api.patchHost(host.id, {
        ...(endpoint !== (host.endpoint ?? "") ? { endpoint } : {}),
        ...(Number(keepalive) > 0 && Number(keepalive) !== host.keepalive
          ? { keepalive: Number(keepalive) }
          : {}),
        ...(consumer !== host.consumer_id ? { consumer_id: consumer } : {}),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-6 z-50">
      <form
        className="rounded-xl bg-white dark:bg-zinc-900 p-6 w-full max-w-md space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <h2 className="text-lg font-medium">
          {t.editHostTitle}: {host.name}
        </h2>
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          placeholder={t.endpointPlaceholder}
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
        />
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          placeholder={t.keepalivePlaceholder}
          value={keepalive}
          onChange={(e) => setKeepalive(e.target.value)}
        />
        <div className="space-y-1">
          <input
            className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
            placeholder={t.searchUsers}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="max-h-36 overflow-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
            {users.data?.map((u) => (
              <button
                key={u.id}
                type="button"
                className={`block w-full text-left px-3 py-1.5 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800 ${
                  consumer === u.id ? "font-medium bg-zinc-100 dark:bg-zinc-800" : ""
                }`}
                onClick={() => setConsumer(u.id)}
              >
                {u.display_name}
                {consumer === u.id && <span className="ml-2 text-xs">✓ {t.invited}</span>}
              </button>
            ))}
          </div>
          {consumer !== host.consumer_id && (
            <p className="text-xs text-amber-600">{t.consumerChangeWarn}</p>
          )}
        </div>
        {save.isError && <p className="text-xs text-red-600">{String(save.error.message)}</p>}
        <div className="flex justify-end gap-2 text-sm">
          <button
            type="button"
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3.5 py-2"
            onClick={onClose}
          >
            {t.cancel}
          </button>
          <button
            type="submit"
            className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 font-medium"
          >
            {t.save}
          </button>
        </div>
      </form>
    </div>
  );
}

// Onboarding: spell out the exact transport commands (wg / awg) for either side.
function Onboarding({ host, side }: { host: Host; side: "proxer" | "client" }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState<string | null>(null);
  const copy = (text: string, tag: string) => {
    void navigator.clipboard.writeText(text);
    setCopied(tag);
    setTimeout(() => setCopied(null), 1500);
  };
  const tool = host.transport === "amneziawg" ? "awg" : "wg";
  const quick = host.transport === "amneziawg" ? "awg-quick" : "wg-quick";
  const cfgDir = host.transport === "amneziawg" ? "/etc/amnezia/amneziawg" : "/etc/wireguard";
  const keyFile = side === "proxer" ? "/etc/dyatel-private.key" : "/etc/dyatel-client.key";
  const confName = side === "proxer" ? host.name : `${host.name}-client`;
  const lines = [
    `# 1. generate your keypair locally (private key never leaves this machine)`,
    `${tool} genkey | tee ${keyFile} | ${tool} pubkey`,
    ...(side === "client"
      ? [
          `# 2. register your public key`,
          `dyatelctl --api https://${location.host} hosts register-consumer-key ${host.id} --wg-pubkey "$(cat ${keyFile}.pub)"`,
        ]
      : []),
    `# ${side === "client" ? "3" : "2"}. fetch the rendered config and fill in the private key`,
    `dyatelctl --api https://${location.host} hosts config ${host.id} ${side} --out ${cfgDir}/${confName}.conf`,
    `sed -i "s|{{PRIVATE_KEY}}|$(cat ${keyFile})|" ${cfgDir}/${confName}.conf`,
    `# ${side === "client" ? "4" : "3"}. bring the tunnel up`,
    `${quick} up ${confName}`,
    `# ${side === "client" ? "5" : "4"}. allow the gateway replies on your firewall (RFC §6 contract)`,
    `ufw allow in proto udp from <gateway-ip> to any port ${host.listen_port}`,
  ].join("\n");

  return (
    <details className="text-sm">
      <summary className="cursor-pointer select-none opacity-70 hover:opacity-100">
        {side === "proxer" ? t.bringUpTitle : t.clientBringUpTitle}
      </summary>
      <div className="mt-2 space-y-2">
        <div className="relative">
          <button
            className="absolute right-2 top-2 rounded bg-zinc-800 text-zinc-200 px-2 py-1 text-xs hover:bg-zinc-700"
            onClick={() => copy(lines, `${host.id}-${side}`)}
          >
            {copied === `${host.id}-${side}` ? t.copied : t.copy}
          </button>
          <pre className="code">{lines}</pre>
        </div>
        <p className="text-xs opacity-60">
          {t.publicEndpoint}: <code>{host.endpoint ?? t.daemonCfgDefault}</code> · {t.listenPort}{" "}
          <code>{host.listen_port}/udp</code> · {t.tunnel} <code>{host.tunnel_ipv4}</code>
        </p>
      </div>
    </details>
  );
}
