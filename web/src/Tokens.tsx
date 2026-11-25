import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";

// Token manager: the panel counterpart of `dyatelctl tokens`. The plaintext
// secret is shown exactly once (the daemon keeps only a digest), so the
// reveal block is deliberately loud and not dismissible by accident.
export default function Tokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: api.tokens });
  const [label, setLabel] = useState("");
  const [minted, setMinted] = useState<{ label: string; token: string } | null>(null);

  const create = useMutation({
    mutationFn: () => api.createToken(label.trim()),
    onSuccess: (t) => {
      setLabel("");
      if (t.token) setMinted({ label: t.label, token: t.token });
      return qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });

  const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : "—");

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">Personal access tokens</h2>
        <p className="text-sm opacity-70 mt-1">
          For the CLI and scripts: <code>dyatelctl --token dyatel_…</code> or{" "}
          <code>DYATEL_TOKEN</code>. Tokens are revoked, never rotated — a leaked
          token is a delete-and-mint, not an edit.
        </p>
      </div>

      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (label.trim()) create.mutate();
        }}
      >
        <input
          className="flex-1 min-w-48 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
          placeholder="label (laptop, vps, ci)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <button
          className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
          type="submit"
          disabled={create.isPending || !label.trim()}
        >
          Mint token
        </button>
      </form>
      {create.isError && (
        <p className="text-xs text-red-600">{String(create.error.message)}</p>
      )}

      {minted && (
        <div className="rounded-xl border border-amber-400 bg-amber-50 dark:bg-amber-950/40 p-4 space-y-2">
          <p className="text-sm font-medium">
            Token “{minted.label}” — copy it now, it is not stored in plaintext.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-white dark:bg-zinc-900 px-3 py-2 text-xs font-mono">
              {minted.token}
            </code>
            <button
              className="rounded-lg border border-amber-500 px-3 py-1.5 text-xs font-medium"
              onClick={() => void navigator.clipboard.writeText(minted.token)}
            >
              Copy
            </button>
            <button className="text-xs underline opacity-70" onClick={() => setMinted(null)}>
              dismiss
            </button>
          </div>
        </div>
      )}

      {tokens.isPending && <p className="text-sm opacity-60">Loading…</p>}
      {tokens.isError && (
        <p className="text-sm text-red-600">{String(tokens.error.message)}</p>
      )}
      {tokens.data && tokens.data.length === 0 && (
        <p className="text-sm opacity-60">No tokens yet.</p>
      )}
      {tokens.data && tokens.data.length > 0 && (
        <table className="w-full text-sm">
          <thead className="text-left text-xs opacity-60">
            <tr>
              <th className="py-2 pr-4 font-normal">Label</th>
              <th className="py-2 pr-4 font-normal">State</th>
              <th className="py-2 pr-4 font-normal">Last used</th>
              <th className="py-2 pr-4 font-normal">Created</th>
              <th className="py-2 font-normal" />
            </tr>
          </thead>
          <tbody>
            {tokens.data.map((t) => (
              <tr key={t.id} className="border-t border-zinc-100 dark:border-zinc-800">
                <td className="py-1.5 pr-4 font-medium">{t.label}</td>
                <td className="py-1.5 pr-4">
                  {t.revoked_at ? (
                    <span className="text-zinc-500">revoked</span>
                  ) : (
                    <span className="text-emerald-700 dark:text-emerald-400">active</span>
                  )}
                </td>
                <td className="py-1.5 pr-4 opacity-70">{fmt(t.last_used_at)}</td>
                <td className="py-1.5 pr-4 opacity-70">{fmt(t.created_at)}</td>
                <td className="py-1.5 text-right">
                  {!t.revoked_at && (
                    <button
                      className="text-xs text-red-600 hover:underline"
                      onClick={() => {
                        if (confirm(`Revoke token ${t.label}? Scripts using it stop working.`))
                          revoke.mutate(t.id);
                      }}
                    >
                      revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revoke.isError && (
        <p className="text-xs text-red-600">{String(revoke.error.message)}</p>
      )}
    </div>
  );
}