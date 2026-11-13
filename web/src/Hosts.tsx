import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import type { Host, Me } from "./types";

// The host list is the whole panel: one card per host with its role badge
// (proxer = owner, client = consumer), forwards table, and the rendered
// configs. RFC §4: no fan-out, exactly one owner and one consumer.
export default function Hosts({ me }: { me: Me }) {
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const [creating, setCreating] = useState(false);

  if (hosts.isPending) return <p className="opacity-60">Loading hosts…</p>;
  if (hosts.isError) return <p className="text-red-600">{String(hosts.error.message)}</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium">Hosts</h2>
        <button
          className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 text-sm font-medium hover:opacity-90"
          onClick={() => setCreating(true)}
        >
          Add host
        </button>
      </div>
      {hosts.data.length === 0 && (
        <p className="opacity-60 text-sm">
          No hosts yet. Register your server as a host to give a client access
          through berg.
        </p>
      )}
      {hosts.data.map((h) => (
        <HostCard key={h.id} host={h} me={me} />
      ))}
      {creating && <CreateHost onClose={() => setCreating(false)} />}
    </div>
  );
}

function role(me: Me, h: Host): "proxer" | "client" | "admin" {
  if (h.owner_id === me.id) return "proxer";
  if (h.consumer_id === me.id) return "client";
  return "admin";
}

function Badge({ r }: { r: string }) {
  const cls =
    r === "proxer"
      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200"
      : r === "client"
        ? "bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-200"
        : "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>{r}</span>;
}

function stateDot(state: string) {
  // Reconciled states are green; anything else (pending, suspended) is amber.
  return state === "active" ? "bg-emerald-500" : "bg-amber-500";
}

function HostCard({ host, me }: { host: Host; me: Me }) {
  const qc = useQueryClient();
  const [showProxer, setShowProxer] = useState(false);
  const [showClient, setShowClient] = useState(false);
  const r = role(me, host);
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
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 rounded-full ${stateDot(host.state)}`} />
            <span className="font-medium">{host.name}</span>
            <Badge r={r} />
          </div>
          <p className="text-xs opacity-60 mt-1 font-mono">
            {host.transport} · {host.listen_port} · {host.tunnel_ipv4}
          </p>
        </div>
        <div className="flex gap-2 text-sm">
          {host.state === "active" ? (
            <button
              className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
              onClick={() => setState.mutate("suspended")}
            >
              Suspend
            </button>
          ) : (
            <button
              className="rounded-lg border border-emerald-400 text-emerald-700 dark:text-emerald-300 px-3 py-1.5 hover:bg-emerald-50 dark:hover:bg-emerald-950"
              onClick={() => setState.mutate("active")}
            >
              Activate
            </button>
          )}
          <button
            className="rounded-lg border border-red-300 text-red-700 dark:text-red-300 px-3 py-1.5 hover:bg-red-50 dark:hover:bg-red-950"
            onClick={() => {
              if (confirm(`Delete host ${host.name}?`)) del.mutate();
            }}
          >
            Delete
          </button>
        </div>
      </div>

      <Forwards hostId={host.id} canCreate={r !== "client"} />

      {r !== "client" && (
        <div className="flex flex-wrap gap-2 text-sm">
          <button
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
            onClick={() => setShowProxer((v) => !v)}
          >
            {showProxer ? "Hide" : "Show"} proxer config
          </button>
          <button
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
            onClick={() => setShowClient((v) => !v)}
          >
            {showClient ? "Hide" : "Show"} client config
          </button>
        </div>
      )}
      {showProxer && <ConfigBlock load={() => api.proxerConfig(host.id)} label="proxer (host side)" />}
      {showClient && <ConfigBlock load={() => api.clientConfig(host.id)} label="client (consumer side)" />}
      {(del.isError || setState.isError) && (
        <p className="text-xs text-red-600">
          {String((del.error ?? setState.error)?.message)}
        </p>
      )}
    </div>
  );
}

function ConfigBlock({ load, label }: { load: () => Promise<string>; label: string }) {
  const q = useQuery({ queryKey: ["config", label, load], queryFn: load, staleTime: 0 });
  return (
    <div className="space-y-2">
      <p className="text-xs opacity-60">Rendered config — {label}</p>
      {q.isPending && <p className="text-xs opacity-60">rendering…</p>}
      {q.isError && <p className="text-xs text-red-600">{String(q.error.message)}</p>}
      {q.data && (
        <div className="relative">
          <button
            className="absolute right-2 top-2 text-xs rounded bg-zinc-800 text-zinc-200 px-2 py-1 hover:bg-zinc-700"
            onClick={() => void navigator.clipboard.writeText(q.data)}
          >
            Copy
          </button>
          <pre className="code">{q.data}</pre>
        </div>
      )}
    </div>
  );
}

function Forwards({ hostId, canCreate }: { hostId: string; canCreate: boolean }) {
  const qc = useQueryClient();
  const fs = useQuery({
    queryKey: ["forwards", hostId],
    queryFn: () => api.forwards(hostId),
  });
  const del = useMutation({
    mutationFn: (fid: string) => api.deleteForward(hostId, fid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["forwards", hostId] }),
  });

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Forwards</h3>
        {canCreate && <ForwardForm hostId={hostId} />}
      </div>
      {fs.isPending && <p className="text-xs opacity-60">…</p>}
      {fs.isError && <p className="text-xs text-red-600">{String(fs.error.message)}</p>}
      {fs.data && fs.data.length === 0 && (
        <p className="text-xs opacity-60">No forwards yet.</p>
      )}
      <table className="w-full text-sm">
        <tbody>
          {fs.data?.map((f) => (
            <tr key={f.id} className="border-t border-zinc-100 dark:border-zinc-800">
              <td className="py-1.5 pr-4 font-mono text-xs">
                :{f.public_port} → :{f.target_port} {f.proto}
              </td>
              <td className="py-1.5 pr-4">{f.label}</td>
              <td className="py-1.5 text-right">
                <button
                  className="text-xs text-red-600 hover:underline"
                  onClick={() => del.mutate(f.id)}
                >
                  delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ForwardForm({ hostId }: { hostId: string }) {
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
        + forward
      </button>
    );
  return (
    <form
      className="flex items-center gap-1.5 text-xs"
      onSubmit={(e) => {
        e.preventDefault();
        if (Number(pub) > 0 && Number(tgt) > 0) create.mutate();
      }}
    >
      <input
        className="w-16 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1"
        placeholder="public"
        value={pub}
        onChange={(e) => setPub(e.target.value)}
      />
      <input
        className="w-16 rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1"
        placeholder="target"
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
        placeholder="label"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
      />
      <button
        className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-2.5 py-1 font-medium"
        type="submit"
      >
        Add
      </button>
      <button type="button" className="underline opacity-60" onClick={() => setOpen(false)}>
        cancel
      </button>
      {create.isError && <span className="text-red-600">{String(create.error.message)}</span>}
    </form>
  );
}

function CreateHost({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [pub, setPub] = useState("");
  const [transport, setTransport] = useState("wireguard");
  const [consumer, setConsumer] = useState("");

  const create = useMutation({
    mutationFn: () =>
      api.createHost({
        name,
        wg_public_key: pub,
        transport,
        consumer_id: consumer,
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
          create.mutate();
        }}
      >
        <h2 className="text-lg font-medium">Register host</h2>
        <p className="text-xs opacity-60">
          BYOK: paste the public key you generated on the host. The core only
          sees public keys.
        </p>
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          placeholder="name (a-z0-9-)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm font-mono"
          placeholder="wg public key"
          value={pub}
          onChange={(e) => setPub(e.target.value)}
        />
        <select
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          value={transport}
          onChange={(e) => setTransport(e.target.value)}
        >
          <option value="wireguard">wireguard</option>
          <option value="amneziawg">amneziawg</option>
          <option value="xray-vless">xray-vless (TLS masking)</option>
        </select>
        <input
          className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm font-mono"
          placeholder="consumer user id (invitation)"
          value={consumer}
          onChange={(e) => setConsumer(e.target.value)}
        />
        {create.isError && (
          <p className="text-xs text-red-600">{String(create.error.message)}</p>
        )}
        <div className="flex justify-end gap-2 text-sm">
          <button
            type="button"
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3.5 py-2"
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 font-medium"
          >
            Create
          </button>
        </div>
      </form>
    </div>
  );
}