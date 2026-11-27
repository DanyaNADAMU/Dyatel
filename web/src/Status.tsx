import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n } from "./i18n";
import type { HostRuntimeStatus, PeerEndpointStatus } from "./types";

function fmtBytes(n = 0): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function PeerCell({
  peer,
  neverLabel,
}: {
  peer?: PeerEndpointStatus;
  neverLabel: string;
}) {
  if (!peer) return <span className="opacity-40">—</span>;
  const sec = Number(peer.last_handshake || 0);
  const hs = sec > 0 ? new Date(sec * 1000).toLocaleTimeString() : neverLabel;
  return (
    <div className="font-mono text-xs space-y-0.5">
      <div>{peer.endpoint && peer.endpoint !== "(none)" ? peer.endpoint : "—"}</div>
      <div className="opacity-65">
        hs: {hs} · ↓{fmtBytes(peer.transfer_rx)} ↑{fmtBytes(peer.transfer_tx)}
      </div>
    </div>
  );
}

// Admin-only operational view of the core (RFC §5 GET /status).
export default function Status() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const s = useQuery({
    queryKey: ["status"],
    queryFn: api.status,
    refetchInterval: 15_000, // mirrors the reconcile cadence
  });
  const rec = useMutation({
    mutationFn: api.reconcile,
    onSuccess: () => {
      setTimeout(() => void qc.invalidateQueries({ queryKey: ["status"] }), 1000);
    },
  });

  if (s.isPending) return <p className="opacity-60">{t.statusLoading}</p>;
  if (s.isError) return <p className="text-red-600">{String(s.error.message)}</p>;

  const checkedAt = typeof s.data._checked_at === "string" ? s.data._checked_at : null;
  const dns = s.data._dns;
  const globalErr =
    s.data._error && typeof s.data._error === "object"
      ? (s.data._error as { last_error?: string }).last_error
      : null;

  const hosts = Object.entries(s.data)
    .filter(([k, v]) => !k.startsWith("_") && v && typeof v === "object")
    .map(([, v]) => v as HostRuntimeStatus)
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs opacity-60 space-x-3">
          <span>{t.statusRefreshed}</span>
          {checkedAt && (
            <span>
              · {t.lastChecked}: {new Date(checkedAt).toLocaleString()}
            </span>
          )}
          {dns && (
            <span>
              · DNS:{" "}
              {!dns.enabled
                ? t.dnsDisabled
                : dns.last_error
                  ? t.dnsError
                  : dns.last_sync
                    ? t.dnsInSync
                    : t.dnsPending}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {rec.isSuccess && <span className="text-xs text-emerald-600">{t.reconcileQueued}</span>}
          <button
            className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-3 py-1.5 text-xs font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50"
            disabled={rec.isPending}
            onClick={() => rec.mutate()}
          >
            {t.reconcileNow}
          </button>
        </div>
      </div>

      {globalErr && (
        <div className="rounded-lg border border-red-300 bg-red-50 dark:bg-red-950/40 p-3 text-xs text-red-700 dark:text-red-300 font-mono">
          {globalErr}
        </div>
      )}

      {dns?.last_error && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 dark:bg-amber-950/40 p-3 text-xs text-amber-800 dark:text-amber-300 font-mono">
          {t.dnsError}: {dns.last_error}
        </div>
      )}

      {hosts.length === 0 ? (
        <p className="text-sm opacity-60">{t.noPeers}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs opacity-60">
              <tr>
                <th className="py-2 pr-4 font-normal">{t.thHost}</th>
                <th className="py-2 pr-4 font-normal">{t.thIface}</th>
                <th className="py-2 pr-4 font-normal">{t.thTransport}</th>
                <th className="py-2 pr-4 font-normal">{t.thPort}</th>
                <th className="py-2 pr-4 font-normal">{t.thProxerPeer}</th>
                <th className="py-2 pr-4 font-normal">{t.thConsumerPeer}</th>
                <th className="py-2 font-normal">{t.thError}</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.name} className="border-t border-zinc-100 dark:border-zinc-800 align-top">
                  <td className="py-2 pr-4 font-medium">
                    <span
                      className={`inline-block h-2 w-2 rounded-full mr-2 ${
                        h.state === "active" ? "bg-emerald-500" : "bg-amber-500"
                      }`}
                    />
                    {h.name}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs">{h.interface || "—"}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{h.transport}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{h.listen_port}</td>
                  <td className="py-2 pr-4">
                    <PeerCell peer={h.endpoints?.proxer} neverLabel={t.never} />
                  </td>
                  <td className="py-2 pr-4">
                    <PeerCell peer={h.endpoints?.consumer} neverLabel={t.never} />
                  </td>
                  <td className="py-2 font-mono text-xs text-red-600">{h.last_error || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
