"use client";

/** "Daten" tab of the administration: start an NVD import and watch it. */

import { useState } from "react";
import { adminFetch } from "@/lib/admin-api";
import { useActivity } from "@/lib/use-activity";
import { IMPORT_DAY_OPTIONS as DAY_OPTIONS, ImportProgress } from "@/components/ImportProgress";

type Mode = "recent" | "full";

export function ImportPanel({ token }: { token: string }) {
  const { importActivity, running, connectionLost, receivedAt, refresh } = useActivity(token, true, true);
  const [mode, setMode] = useState<Mode>("recent");
  const [days, setDays] = useState(7);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setError("");
    setBusy(true);
    try {
      await adminFetch(token, "/import", { method: "POST", body: { mode, days } });
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
          Server dabei neu, bricht der Import ab und kann neu gestartet werden.
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
              <strong>Kompletter Bestand</strong> (rund 300.000 CVEs). Gemessen laufen etwa 160 CVEs pro Minute, das
              dauert deshalb über einen Tag.
            </span>
          </label>
        </fieldset>

        {error && (
          <p className="mt-3 text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <button
          onClick={start}
          disabled={running || busy}
          className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {running ? "Import läuft" : "Import starten"}
        </button>
      </section>

      {importActivity && (
        <section className="rounded-2xl bg-white p-6 dark:bg-gray-800" aria-label="Stand des Imports">
          <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">{importActivity.title}</h2>
          <ImportProgress status={importActivity} receivedAt={receivedAt} connectionLost={connectionLost} />
        </section>
      )}
    </div>
  );
}
