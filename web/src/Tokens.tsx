import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n } from "./i18n";

// Token manager: the panel counterpart of `dyatelctl tokens`. The plaintext
// secret is shown exactly once (the daemon keeps only a digest), so the
// reveal block is deliberately loud and not dismissible by accident.
export default function Tokens() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: api.tokens });
  const [label, setLabel] = useState("");
  const [minted, setMinted] = useState<{ label: string; token: string } | null>(null);

  const create = useMutation({
    mutationFn: () => api.createToken(label.trim()),
    onSuccess: (tok) => {
      setLabel("");
      if (tok.token) setMinted({ label: tok.label, token: tok.token });
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
        <h2 className="text-lg font-medium">{t.tokensTitle}</h2>
        <p className="text-sm opacity-70 mt-1">{t.tokensDesc}</p>
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
          placeholder={t.tokenLabelPlaceholder}
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <button
          className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-3.5 py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
          type="submit"
          disabled={create.isPending || !label.trim()}
        >
          {t.mintToken}
        </button>
      </form>
      {create.isError && <p className="text-xs text-red-600">{String(create.error.message)}</p>}

      {minted && (
        <div className="rounded-xl border border-amber-400 bg-amber-50 dark:bg-amber-950/40 p-4 space-y-2">
          <p className="text-sm font-medium">
            “{minted.label}” — {t.tokenCopyOnce}
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-white dark:bg-zinc-900 px-3 py-2 text-xs font-mono">
              {minted.token}
            </code>
            <button
              className="rounded-lg border border-amber-500 px-3 py-1.5 text-xs font-medium"
              onClick={() => void navigator.clipboard.writeText(minted.token)}
            >
              {t.copy}
            </button>
            <button className="text-xs underline opacity-70" onClick={() => setMinted(null)}>
              {t.dismiss}
            </button>
          </div>
        </div>
      )}

      {tokens.isPending && <p className="text-sm opacity-60">{t.loading}</p>}
      {tokens.isError && <p className="text-sm text-red-600">{String(tokens.error.message)}</p>}
      {tokens.data && tokens.data.length === 0 && <p className="text-sm opacity-60">{t.noTokens}</p>}
      {tokens.data && tokens.data.length > 0 && (
        <table className="w-full text-sm">
          <thead className="text-left text-xs opacity-60">
            <tr>
              <th className="py-2 pr-4 font-normal">{t.thLabel}</th>
              <th className="py-2 pr-4 font-normal">{t.thState}</th>
              <th className="py-2 pr-4 font-normal">{t.thLastUsed}</th>
              <th className="py-2 pr-4 font-normal">{t.thCreated}</th>
              <th className="py-2 font-normal" />
            </tr>
          </thead>
          <tbody>
            {tokens.data.map((tok) => (
              <tr key={tok.id} className="border-t border-zinc-100 dark:border-zinc-800">
                <td className="py-1.5 pr-4 font-medium">{tok.label}</td>
                <td className="py-1.5 pr-4">
                  {tok.revoked_at ? (
                    <span className="text-zinc-500">{t.stateRevoked}</span>
                  ) : (
                    <span className="text-emerald-700 dark:text-emerald-400">{t.stateActive}</span>
                  )}
                </td>
                <td className="py-1.5 pr-4 opacity-70">{fmt(tok.last_used_at)}</td>
                <td className="py-1.5 pr-4 opacity-70">{fmt(tok.created_at)}</td>
                <td className="py-1.5 text-right">
                  {!tok.revoked_at && (
                    <button
                      className="text-xs text-red-600 hover:underline"
                      onClick={() => {
                        if (confirm(`${t.confirmRevoke} ${tok.label}? ${t.scriptsStop}`))
                          revoke.mutate(tok.id);
                      }}
                    >
                      {t.revoke}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revoke.isError && <p className="text-xs text-red-600">{String(revoke.error.message)}</p>}
    </div>
  );
}
