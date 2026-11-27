import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n } from "./i18n";

// Audit feed. Admins read every action (moderation); everyone else sees only
// their own trail — scoping happens server-side, the UI just renders.
export default function Events({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useI18n();
  const evs = useQuery({
    queryKey: ["events", isAdmin],
    queryFn: () => api.events(isAdmin ? 200 : 100),
  });

  if (evs.isPending) return <p className="text-sm opacity-60">{t.loading}</p>;
  if (evs.isError) return <p className="text-sm text-red-600">{String(evs.error.message)}</p>;
  if (evs.data.length === 0) return <p className="text-sm opacity-60">{t.noEvents}</p>;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-medium">{t.activityTitle}</h2>
        <p className="text-sm opacity-70 mt-1">{isAdmin ? t.activityAll : t.activityOwn}</p>
      </div>
      <table className="w-full text-sm">
        <thead className="text-left text-xs opacity-60">
          <tr>
            <th className="py-2 pr-4 font-normal">{t.thWhen}</th>
            <th className="py-2 pr-4 font-normal">{t.thAction}</th>
            <th className="py-2 pr-4 font-normal">{t.thObject}</th>
            <th className="py-2 font-normal">{t.thAuth}</th>
          </tr>
        </thead>
        <tbody>
          {evs.data.map((e) => (
            <tr key={e.id} className="border-t border-zinc-100 dark:border-zinc-800">
              <td className="py-1.5 pr-4 opacity-70 whitespace-nowrap">
                {new Date(e.at).toLocaleString()}
              </td>
              <td className="py-1.5 pr-4 font-mono text-xs">{e.action}</td>
              <td className="py-1.5 pr-4 font-mono text-xs opacity-70">
                {e.object_type}:{e.object_id.slice(0, 8)}
              </td>
              <td className="py-1.5 text-xs opacity-60">{e.auth_method}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
