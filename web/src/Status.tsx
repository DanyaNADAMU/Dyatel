import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

// Admin-only operational view of the core (RFC §5 GET /status). Rendered as
// a key/value block because the shape is deliberately loose in the core.
export default function Status() {
  const s = useQuery({
    queryKey: ["status"],
    queryFn: api.status,
    refetchInterval: 15_000, // mirrors the reconcile cadence
  });
  if (s.isPending) return <p className="opacity-60">Loading status…</p>;
  if (s.isError) return <p className="text-red-600">{String(s.error.message)}</p>;
  return (
    <div className="space-y-2">
      <p className="text-xs opacity-60">refreshed every 15s (reconcile cadence)</p>
      <table className="w-full text-sm">
        <tbody>
          {Object.entries(s.data).map(([k, v]) => (
            <tr key={k} className="border-t border-zinc-100 dark:border-zinc-800">
              <td className="py-1.5 pr-6 font-mono text-xs opacity-70">{k}</td>
              <td className="py-1.5 font-mono text-xs">{String(JSON.stringify(v))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}