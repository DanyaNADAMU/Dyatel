import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { complete, mgr, signin } from "./auth";
import { clearCred, getCred, setCred, type Credential } from "./session";
import { LangProvider, useI18n } from "./i18n";
import Hosts from "./Hosts";
import Status from "./Status";
import Tokens from "./Tokens";
import Events from "./Events";

// Top-level auth state machine. Two entry paths, one session shape:
//  - Authentik OIDC code flow (PKCE) for normal humans;
//  - break-glass Basic (the single fallback admin) for Authentik outages.
export default function App() {
  return (
    <LangProvider>
      <AppInner />
    </LangProvider>
  );
}

function LangToggle() {
  const { lang, setLang } = useI18n();
  return (
    <button
      type="button"
      className="rounded border border-zinc-300 dark:border-zinc-700 px-2 py-0.5 text-xs font-mono opacity-80 hover:opacity-100"
      onClick={() => setLang(lang === "ru" ? "en" : "ru")}
      title="Switch language / Переключить язык"
    >
      {lang.toUpperCase()}
    </button>
  );
}

function AppInner() {
  const { t } = useI18n();
  const [cred, setCredState] = useState<Credential | null>(getCred());
  const [busy, setBusy] = useState(getCred() === null);
  const [authErr, setAuthErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const hasCallbackParams =
        location.search.includes("code=") ||
        location.search.includes("error=") ||
        location.hash.includes("code=");
      try {
        // Returning from Authentik: complete the code flow, keep the access
        // token in sessionStorage (tab-lifetime only).
        if (hasCallbackParams) {
          const u = await complete();
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
      } catch (e) {
        setAuthErr(`${t.oidcFailed}: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        if (hasCallbackParams) {
          history.replaceState(null, "", location.pathname);
        }
        // A failed callback must still show the login screen, not hang here.
        setBusy(false);
      }
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

  if (busy) return <Shell>{t.loading}</Shell>;
  if (!cred)
    return (
      <Login
        initialError={authErr}
        onOidc={signin}
        onBasic={(c) => {
          setCred(c);
          setCredState(c);
        }}
      />
    );

  return <Panel cred={cred} onSignout={onSignout} />;
}

function Login({
  initialError,
  onOidc,
  onBasic,
}: {
  initialError: string | null;
  onOidc: () => Promise<void>;
  onBasic: (c: Credential) => void;
}) {
  const { t } = useI18n();
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState<string | null>(initialError);

  const tryOidc = async () => {
    // Surface redirect failures (bad authority/discovery) instead of dying
    // silently — a swallowed rejection reads as "the button does nothing".
    setErr(null);
    try {
      await onOidc();
    } catch (e) {
      setErr(`${t.oidcFailed}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const tryBasic = async () => {
    // Verify against /me before storing anything: a wrong break-glass
    // password must fail here, not on every later call.
    const header = `Basic ${btoa(`${user}:${pass}`)}`;
    const r = await fetch("/api/v1/me", { headers: { Authorization: header } });
    if (r.ok) {
      onBasic({ auth: "basic", header });
    } else {
      setErr(`${t.authFailed} (${r.status})`);
    }
  };

  return (
    <Shell>
      <div className="flex justify-end">
        <LangToggle />
      </div>
      <div className="max-w-sm mx-auto mt-20 space-y-6">
        <div className="text-center">
          <h1 className="text-3xl font-semibold">Dyatel</h1>
          <p className="text-sm opacity-70 mt-2">{t.tagline}</p>
        </div>
        <button
          className="w-full rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 px-4 py-2.5 font-medium hover:opacity-90"
          onClick={() => void tryOidc()}
        >
          {t.signInAuthentik}
        </button>
        {err && <p className="text-xs text-red-600">{err}</p>}
        <details className="text-sm">
          <summary className="opacity-60 cursor-pointer select-none">{t.breakGlass}</summary>
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
              placeholder={t.fallbackUser}
              value={user}
              onChange={(e) => setUser(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2"
              type="password"
              placeholder={t.password}
              value={pass}
              onChange={(e) => setPass(e.target.value)}
            />
            <button
              className="w-full rounded-lg border border-zinc-400 dark:border-zinc-600 px-3 py-2 font-medium"
              type="submit"
            >
              {t.signInBasic}
            </button>
          </form>
        </details>
      </div>
    </Shell>
  );
}

function Panel({ cred, onSignout }: { cred: Credential; onSignout: () => void }) {
  const { t } = useI18n();
  const me = useQuery({ queryKey: ["me", cred], queryFn: api.me });
  const [tab, setTab] = useState<"hosts" | "tokens" | "activity" | "status">("hosts");

  if (me.isPending) return <Shell>{t.loading}</Shell>;
  if (me.isError)
    return (
      <Shell>
        <div className="mx-auto mt-24 text-center space-y-4">
          <p className="text-red-600">
            {t.apiError}: {String(me.error.message)}
          </p>
          <button className="underline" onClick={onSignout}>
            {t.signOut}
          </button>
        </div>
      </Shell>
    );

  const tabLabels: Record<"hosts" | "tokens" | "activity" | "status", string> = {
    hosts: t.tabHosts,
    tokens: t.tabTokens,
    activity: t.tabActivity,
    status: t.tabStatus,
  };

  return (
    <Shell>
      <header className="flex items-center justify-between mb-2">
        <h1 className="text-2xl font-semibold">Dyatel</h1>
        <div className="flex items-center gap-3 text-sm">
          <LangToggle />
          <span>
            {me.data.name}
            <span className="ml-1.5 opacity-50">{cred.auth}</span>
            {me.data.is_admin && (
              <span className="ml-1.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200 px-1.5 py-0.5 text-xs">
                {t.admin}
              </span>
            )}
          </span>
          <button className="underline opacity-70 hover:opacity-100" onClick={onSignout}>
            {t.signOut}
          </button>
        </div>
      </header>
      <nav className="flex gap-1 text-sm border-b border-zinc-200 dark:border-zinc-800 mb-6">
        {(["hosts", "tokens", "activity", "status"] as const)
          // status is the admin drift report: no point showing a 403 tab to
          // the users who cannot read it.
          .filter((k) => k !== "status" || me.data.is_admin)
          .map((k) => (
            <button
              key={k}
              className={`px-3 py-2 -mb-px border-b-2 ${
                tab === k
                  ? "border-zinc-900 dark:border-zinc-100 font-medium"
                  : "border-transparent opacity-60 hover:opacity-100"
              }`}
              onClick={() => setTab(k)}
            >
              {tabLabels[k]}
            </button>
          ))}
      </nav>
      {tab === "hosts" && <Hosts me={me.data} />}
      {tab === "tokens" && <Tokens />}
      {tab === "activity" && <Events isAdmin={me.data.is_admin} />}
      {tab === "status" && <Status />}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return <div className="max-w-4xl mx-auto px-6 py-8">{children}</div>;
}
