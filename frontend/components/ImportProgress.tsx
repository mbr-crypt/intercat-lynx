"use client";

/**
 * Live display of the data import: phases, bar, counter, running time, last sign
 * of life and a short event log. Used by the setup assistant, the activity icon
 * in the header and the "Daten" page of the administration.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2, XCircle } from "lucide-react";
import type { ImportStatus } from "@/lib/admin-api";

export const IMPORT_PHASES: { id: string; label: string }[] = [
  { id: "nvd", label: "CVE-Daten von der NVD laden" },
  { id: "cisa_kev", label: "Aktiv ausgenutzte Lücken abgleichen (CISA KEV)" },
  { id: "stats", label: "Statistik berechnen" },
  { id: "catalog", label: "Produktkatalog aufbauen" },
];

/** Time spans offered for "recent" imports, with what to expect (measured on the VM test: ~160 CVEs/min). */
export const IMPORT_DAY_OPTIONS: { days: number; hint: string }[] = [
  { days: 1, hint: "wenige hundert bis tausend CVEs, einige Minuten" },
  { days: 7, hint: "etwa 25.000 CVEs, gemessen rund 2,5 Stunden" },
  { days: 30, hint: "etwa 50.000 CVEs, mehrere Stunden" },
  { days: 120, hint: "sehr viele, nur wenn nötig" },
];

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m} Min. ${String(s % 60).padStart(2, "0")} s` : `${s} s`;
}

interface Props {
  status: ImportStatus;
  /** Timestamp (ms) at which `status` arrived, so the timers keep counting between two polls */
  receivedAt: number;
  /** The server did not answer the last few requests */
  connectionLost?: boolean;
}

export function ImportProgress({ status, receivedAt, connectionLost = false }: Props) {
  const [, setTick] = useState(0);
  const running = status.state === "running";

  // One-second clock so the running time keeps counting between two polls
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [running]);

  const pct = status.total ? Math.min(100, Math.round(((status.processed || 0) / status.total) * 100)) : null;
  const phaseIndex = IMPORT_PHASES.findIndex((p) => p.id === status.phase);
  const sincePoll = running ? (Date.now() - receivedAt) / 1000 : 0;
  const elapsed = (status.elapsed_seconds ?? 0) + sincePoll;
  const silent = (status.seconds_since_heartbeat ?? 0) + sincePoll;
  const determinate = status.phase === "nvd" && pct !== null;
  const failed = status.state === "error" || status.state === "interrupted";

  return (
    <div className="space-y-3">
      <ol className="space-y-1 text-sm">
        {IMPORT_PHASES.map((p, i) => {
          const finished = status.state === "done" || (phaseIndex >= 0 && i < phaseIndex);
          const active = running && i === phaseIndex;
          const broken = failed && i === phaseIndex;
          return (
            <li key={p.id} className="flex items-center gap-2">
              {finished ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 text-green-600" aria-hidden />
              ) : active ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-primary" aria-hidden />
              ) : broken ? (
                <XCircle className="h-4 w-4 shrink-0 text-red-600" aria-hidden />
              ) : (
                <span className="h-4 w-4 shrink-0 rounded-full border border-gray-300 dark:border-gray-600" aria-hidden />
              )}
              <span className={finished || active || broken ? "text-gray-900 dark:text-white" : "text-gray-500"}>
                {p.label}
                <span className="sr-only">
                  {finished ? " (erledigt)" : active ? " (läuft)" : broken ? " (fehlgeschlagen)" : " (wartet)"}
                </span>
              </span>
            </li>
          );
        })}
      </ol>

      <div
        className="relative h-3 w-full overflow-hidden rounded bg-gray-200 dark:bg-gray-700"
        role="progressbar"
        aria-label="Fortschritt des Datenimports"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={status.state === "done" ? 100 : determinate ? pct ?? undefined : undefined}
      >
        {status.state === "done" || determinate ? (
          <div
            className="h-3 bg-primary transition-all duration-500"
            style={{ width: `${status.state === "done" ? 100 : pct}%` }}
          />
        ) : running ? (
          <div
            className="lynx-indeterminate absolute inset-y-0 left-0 w-1/4 rounded bg-primary"
            style={{ animation: "lynx-indeterminate 1.6s ease-in-out infinite" }}
          />
        ) : null}
      </div>

      <div className="space-y-1 text-sm text-gray-700 dark:text-gray-300" role="status" aria-live="polite">
        <p>
          {!failed && status.message}
          {determinate && running && (
            <>
              {" – "}
              <strong>{(status.processed || 0).toLocaleString("de-DE")}</strong> von{" "}
              {status.total?.toLocaleString("de-DE")} CVEs ({pct} %)
            </>
          )}
        </p>
        {running && status.detail && <p className="text-gray-600 dark:text-gray-400">{status.detail}</p>}
      </div>

      {running && (
        <p className="text-xs text-gray-500">
          Laufzeit {formatDuration(elapsed)} · letzte Rückmeldung des Servers vor {formatDuration(silent)}
        </p>
      )}
      {!running && status.elapsed_seconds !== undefined && status.state !== "idle" && (
        <p className="text-xs text-gray-500">Laufzeit {formatDuration(status.elapsed_seconds)}</p>
      )}
      {running && silent > 30 && !connectionLost && (
        <p className="text-sm text-amber-700 dark:text-amber-400" role="alert">
          <AlertTriangle className="mr-1 inline h-4 w-4" aria-hidden />
          Seit {formatDuration(silent)} keine Rückmeldung vom Import. Das kann bei sehr langsamer Verbindung zur NVD
          vorkommen. Nach 90 Sekunden ohne Rückmeldung gilt der Import als abgebrochen und kann neu gestartet werden.
        </p>
      )}
      {running && connectionLost && (
        <p className="text-sm text-amber-700 dark:text-amber-400" role="alert">
          <AlertTriangle className="mr-1 inline h-4 w-4" aria-hidden />
          Der Server antwortet gerade nicht. Der Import läuft möglicherweise weiter, diese Seite versucht es automatisch
          erneut.
        </p>
      )}

      {status.log && status.log.length > 0 && (
        <details className="text-xs" open={failed}>
          <summary className="cursor-pointer text-gray-600 dark:text-gray-400">
            Ereignisprotokoll ({status.log.length})
          </summary>
          <ul className="mt-2 space-y-0.5 font-mono text-gray-600 dark:text-gray-400">
            {status.log.map((e, i) => (
              <li key={`${e.t}-${i}`}>
                <span className="text-gray-400">{new Date(e.t).toLocaleTimeString("de-DE")}</span> {e.text}
              </li>
            ))}
          </ul>
        </details>
      )}

      {failed && (
        <div className="space-y-1 text-sm text-red-600" role="alert">
          <p>{status.message}</p>
          <p className="text-gray-600 dark:text-gray-400">
            Bereits geladene CVEs bleiben erhalten, ein neuer Start aktualisiert sie nur.
          </p>
        </div>
      )}
    </div>
  );
}
