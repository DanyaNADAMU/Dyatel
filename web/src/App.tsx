import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { complete, mgr, signin } from "./auth";
import { clearCred, getCred, setCred, type Credential } from "./session";
import Hosts from "./Hosts";
import Status from "./Status";

// Top-level auth state machine. Two entry paths, one session shape:
//  - Authentik OIDC code flow (PKCE) for normal humans;
//  - break-glass Basic (the single fallback admin) for Authentik outages.
export default function App() {
  const [cred, setCredState] = useState<Credential | null>(getCred());
  const [busy, setBusy] = useState(getCred() === null);

  useEffect(() => {
    (async () => {
      // Returning from Authentik: complete the code flow, keep the access
      // token in sessionStorage (tab-lifetime only).
      if (location.search.includes("code=") || location.hash.includes("code=")) {
        const u = await complete();
        history.replaceState(null, "", location.pathname);
        if (u?.access_token) {
          const c: Credential = { auth: "oidc", token: u.access_token };
          setCred(c);
          setCredState(c);
        }
      } else {
        const u = await mgr.getUser();
        if (u && !u.expired && u.access_token) {
          const c: Credential = { auth: "oidc", token: u.access_token };
          setCred(c);
          setCredState(c);
        }
      }
      setBusy(false);
    })();
  }, []);

  const onSignout = () => {
    const c = getCred();
    clearCred();
    setCredState(null);
    void mgr.removeUser();
    // Basic sessions end locally; OIDC ends at Authentik too.
    if (c?.auth === "oidc") location.href = `${location.origin}${location.pathname}`;
  };

  if (busy) return <Shell>Loading…</Shell>;
  if (!cred) return <Login onOidc={() => void signin()} onBasic={(c) => { setCred(c); setCredState(c); }} />;

  return <Panel cred={cred} onSignout={onSignout} />;
}

function Login({
  onOidc,
  onBasic,
}: {
  onOidc: () => void;
  onBasic: (c: Credential) => void;
}) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const tryBasic = async () => {
    // Verify against /me before storing anything: a wrong break-glass
    // password must fail here, not on every later call.
    const header = `Basic ${btoa(`${user}:${pass}`)}`;
    const r = await fetch("/api/v1/me", { headers: { Authorization: header } });
    if (r.ok) {
      onBasic({ auth: "basic", header });
    } else {
      setErr(`authentication failed (${r.status})`);
    }
  };

  return (
    <Shell>
      <div className="max-w-sm mx-auto mt-24 space-y-6">
        <div className="text-center">
          <h1 className="text-3xl font-semibold">Dyatel</h1>
          <p className="text-sm opacity-70 mt-2">
            Tunnel manager — hosts, forwards and rendered configs for proxers
            and clients.
          </p>
        </div>
        <button
          className="w-full rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-4 py-2.5 font-medium hover:opacity-90"
          onClick={onOidc}
        >
          Sign in with Authentik
        </button>
        <details className="text-sm">
          <summary className="opacity-60 cursor-pointer select-none">
            Break-glass admin access
          </summary>
          <form
            className="mt-3 space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              setErr(null);
              void tryBasic();
            }}
          >
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2"
              placeholder="fallback admin user"
              value={user}
              onChange={(e) => setUser(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2"
              type="password"
              placeholder="password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
            />
            <button
              className="w-full rounded-lg border border-zinc-400 dark:border-zinc-600 px-3 py-2 font-medium"
              type="submit"
            >
              Sign in (Basic)
            </button>
            {err && <p className="text-xs text-red-600">{err}</p>}
          </form>
        </details>
      </div>
    </Shell>
  );
}

function Panel({ cred, onSignout }: { cred: Credential; onSignout: () => void }) {
  const me = useQuery({ queryKey: ["me", cred], queryFn: api.me });
  const [tab, setTab] = useState<"hosts" | "status">("hosts");

  if (me.isPending) return <Shell>Loading…</Shell>;
  if (me.isError)
    return (
      <Shell>
        <div className="mx-auto mt-24 text-center space-y-4">
          <p className="text-red-600">API error: {String(me.error.message)}</p>
          <button className="underline" onClick={onSignout}>
            Sign out
          </button>
        </div>
      </Shell>
    );

  return (
    <Shell>
      <header className="flex items-center justify-between mb-2">
        <h1 className="text-2xl font-semibold">Dyatel</h1>
        <div className="flex items-center gap-4 text-sm">
          <span>
            {me.data.name}
            <span className="ml-1.5 opacity-50">{cred.auth}</span>
            {me.data.is_admin && (
              <span className="ml-1.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200 px-1.5 py-0.5 text-xs">
                admin
              </span>
            )}
          </span>
          <button className="underline opacity-70 hover:opacity-100" onClick={onSignout}>
            Sign out
          </button>
        </div>
      </header>
      <nav className="flex gap-1 text-sm border-b border-zinc-200 dark:border-zinc-800 mb-6">
        {(["hosts", "status"] as const).map((t) => (
          <button
            key={t}
            className={`px-3 py-2 -mb-px border-b-2 ${
              tab === t
                ? "border-zinc-900 dark:border-zinc-100 font-medium"
                : "border-transparent opacity-60 hover:opacity-100"
            }`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>
      {tab === "hosts" ? <Hosts me={me.data} /> : <Status />}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return <div className="max-w-4xl mx-auto px-6 py-8">{children}</div>;
}