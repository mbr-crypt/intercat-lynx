"use client";

/** "Daten" tab of the administration: start an NVD import and watch it. */

import { useState } from "react";
import { adminFetch, type ScheduledTask } from "@/lib/admin-api";
import { useActivity } from "@/lib/use-activity";
import { BsiCard } from "@/components/admin/BsiCard";
import { IMPORT_DAY_OPTIONS as DAY_OPTIONS, ImportProgress } from "@/components/ImportProgress";

type Mode = "recent" | "full";

export function ImportPanel({ token }: { token: string }) {
  const { importActivity, scheduled, running, connectionLost, rateLimited, receivedAt, refresh } = useActivity(token, true);
  const [mode, setMode] = useState<Mode>("recent");
  const [days, setDays] = useState(7);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const canResume = !running && importActivity?.can_resume === true;

  const start = async (resume = false) => {
    setError("");
    setBusy(true);
    try {
      await adminFetch(token, "/import", { method: "POST", body: { mode, days, resume } });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import konnte nicht gestartet werden");
    } finally {
      setBusy(false);
    }
  };

  const hint = DAY_OPTIONS.find((o) => o.days === days)?.hint;

  return (
    <div className="space-y-6">
      <section className="rounded-2xl bg-white p-6 dark:bg-gray-800">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Daten nachladen</h2>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Lädt CVEs von der NVD und gleicht die aktiv ausgenutzten (CISA KEV) ab. Gezählt werden alle CVEs, die im
          Zeitraum <strong>geändert</strong> wurden, nicht nur neue. Bereits vorhandene werden aktualisiert. Läuft der
          Server dabei neu, bricht der Import ab und kann dort fortgesetzt werden, wo er aufgehört hat.
        </p>

        <fieldset className="mt-4 space-y-3 text-sm" disabled={running || busy}>
          <label className="flex items-start gap-2">
            <input type="radio" className="mt-1" checked={mode === "recent"} onChange={() => setMode("recent")} />
            <span>
              <strong>Letzte Tage</strong>
              {mode === "recent" && (
                <span className="ml-2">
                  <select
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                    className="rounded border bg-white px-1 dark:bg-gray-800"
                    aria-label="Zeitraum in Tagen"
                  >
                    {DAY_OPTIONS.map((o) => (
                      <option key={o.days} value={o.days}>
                        {o.days} {o.days === 1 ? "Tag" : "Tage"}
                      </option>
                    ))}
                  </select>
                  {hint && <span className="ml-2 text-gray-500">{hint}</span>}
                </span>
              )}
            </span>
          </label>
          <label className="flex items-start gap-2">
            <input type="radio" className="mt-1" checked={mode === "full"} onChange={() => setMode("full")} />
            <span>
              <strong>Kompletter Bestand</strong> (rund 300.000 CVEs). Die Dauer ist noch nicht gemessen; bei
              den kurzen Zeiträumen liefen rund 80 CVEs pro Sekunde, daraus ergibt sich grob eine Stunde. Er kann
              abgebrochen und später fortgesetzt werden.
            </span>
          </label>
        </fieldset>

        {error && (
          <p className="mt-3 text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          {canResume && (
            <button
              onClick={() => start(true)}
              disabled={busy}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              Unterbrochenen Import fortsetzen
            </button>
          )}
          <button
            onClick={() => start(false)}
            disabled={running || busy}
            className={
              canResume
                ? "rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700"
                : "rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            }
          >
            {running ? "Import läuft" : canResume ? "Neu von vorn starten" : "Import starten"}
          </button>
        </div>
      </section>

      {importActivity && (
        <section className="rounded-2xl bg-white p-6 dark:bg-gray-800" aria-label="Stand des Imports">
          <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">{importActivity.title}</h2>
          <ImportProgress status={importActivity} receivedAt={receivedAt} connectionLost={connectionLost} rateLimited={rateLimited} />
        </section>
      )}

      <BsiCard token={token} />

      <ScheduledTasks tasks={scheduled} />
    </div>
  );
}

const STATE_LABEL: Record<ScheduledTask["state"], { text: string; className: string }> = {
  never: { text: "noch nicht gelaufen", className: "text-gray-500" },
  running: { text: "läuft", className: "text-blue-600 dark:text-blue-400" },
  ok: { text: "in Ordnung", className: "text-green-700 dark:text-green-400" },
  error: { text: "Fehler", className: "text-red-600 dark:text-red-400" },
  interrupted: { text: "unterbrochen", className: "text-amber-700 dark:text-amber-400" },
};

function formatTime(iso?: string): string {
  if (!iso) return "–";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "–" : d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

/** Last run of every scheduled background task (Celery worker). */
function ScheduledTasks({ tasks }: { tasks: ScheduledTask[] }) {
  if (tasks.length === 0) return null;
  return (
    <section className="rounded-2xl bg-white p-6 dark:bg-gray-800" aria-label="Geplante Aufgaben">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Geplante Aufgaben</h2>
      <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
        Das läuft regelmäßig von selbst im Hintergrund (Celery, ein Zeitplaner im Worker-Container). Hier steht, wann
        jede Aufgabe zuletzt gelaufen ist und wie sie ausging.
      </p>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead>
            <tr className="border-b border-gray-200 text-gray-500 dark:border-gray-700">
              <th className="py-2 pr-4 font-medium">Aufgabe</th>
              <th className="py-2 pr-4 font-medium">Zeitplan</th>
              <th className="py-2 pr-4 font-medium">Zuletzt</th>
              <th className="py-2 font-medium">Ergebnis</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t) => {
              const label = STATE_LABEL[t.state] ?? STATE_LABEL.never;
              return (
                <tr key={t.id} className="border-b border-gray-100 align-top last:border-0 dark:border-gray-700/60">
                  <td className="py-2 pr-4 text-gray-900 dark:text-white">{t.title}</td>
                  <td className="py-2 pr-4 text-gray-600 dark:text-gray-400">{t.schedule}</td>
                  <td className="py-2 pr-4 text-gray-600 dark:text-gray-400">{formatTime(t.finished_at ?? t.started_at)}</td>
                  <td className="py-2">
                    <span className={`font-medium ${label.className}`}>{label.text}</span>
                    {t.message && <span className="ml-2 text-gray-500">{t.message}</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
