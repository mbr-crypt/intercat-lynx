"use client";

import { useCallback, useEffect, useState } from "react";
import { adminFetch, AUDIT_LABEL, formatDate, type AuditEvent, type Paged } from "@/lib/admin-api";
import { secondaryButton } from "./Modal";

export function AuditPanel({ token }: { token: string }) {
  const [data, setData] = useState<Paged<AuditEvent> | null>(null);
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await adminFetch<Paged<AuditEvent>>(token, `/users/audit?page=${page}&page_size=25`));
      setError("");
    } catch (e: any) {
      setError(e.message);
    }
  }, [token, page]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Wer hat wann was an Konten geändert. Passwörter und Tokens stehen nie im Protokoll.
      </p>
      {error && (
        <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
          {error}
        </p>
      )}
      <div className="overflow-x-auto rounded-2xl bg-white dark:bg-gray-800">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead className="border-b border-gray-200 text-xs uppercase tracking-wide text-gray-500 dark:border-gray-700 dark:text-gray-400">
            <tr>
              <th className="px-4 py-3 font-semibold">Zeitpunkt</th>
              <th className="px-4 py-3 font-semibold">Aktion</th>
              <th className="px-4 py-3 font-semibold">Durch</th>
              <th className="px-4 py-3 font-semibold">Betrifft</th>
              <th className="px-4 py-3 font-semibold">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {data?.items.map((e) => (
              <tr key={e.id}>
                <td className="whitespace-nowrap px-4 py-3 text-gray-600 dark:text-gray-400">{formatDate(e.created_at)}</td>
                <td className="px-4 py-3 text-gray-900 dark:text-white">{AUDIT_LABEL[e.action] ?? e.action}</td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300">{e.actor_username ?? "-"}</td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300">{e.target_username ?? "-"}</td>
                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{e.detail ?? ""}</td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  Noch keine Einträge.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {data && (
        <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
          <span>{data.total} Einträge</span>
          <div className="flex items-center gap-2">
            <button className={secondaryButton} disabled={page <= 1} onClick={() => setPage(page - 1)}>
              Zurück
            </button>
            <span>
              Seite {page} von {totalPages}
            </span>
            <button className={secondaryButton} disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
              Weiter
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
