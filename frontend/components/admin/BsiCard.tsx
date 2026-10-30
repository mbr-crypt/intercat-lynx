"use client";

/** BSI CERT-Bund in the "Daten" tab: switch, last run, fetch now. */

import { useCallback, useEffect, useState } from "react";
import { bsiAdminFetch, type BsiStatus } from "@/lib/bsi-api";

function formatTime(iso: string | null): string {
  if (!iso) return "noch nie";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "noch nie" : d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

export function BsiCard({ token }: { token: string }) {
  const [status, setStatus] = useState<BsiStatus | null>(null);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await bsiAdminFetch<BsiStatus>(token, "/status"));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Status nicht lesbar");
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (enabled: boolean) => {
    setBusy(true);
    setNote("");
    try {
      setStatus(await bsiAdminFetch<BsiStatus>(token, "/settings", { method: "PUT", body: { enabled } }));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Nicht gespeichert");
    } finally {
      setBusy(false);
    }
  };

  const fetchNow = async () => {
    setBusy(true);
    setNote("");
    try {
      await bsiAdminFetch(token, "/fetch", { method: "POST" });
      setNote("Abruf gestartet. Das Ergebnis erscheint gleich unter „Geplante Aufgaben“.");
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Abruf nicht gestartet");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-2xl bg-white p-6 dark:bg-gray-800" aria-label="BSI CERT-Bund">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white">BSI CERT-Bund</h2>
      <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
        Übernimmt die Warnmeldungen des BSI (CSAF-Feed, öffentlich, Einstufung TLP:WHITE) alle drei Stunden. Gespeichert
        werden Nummer, Titel, Einstufung und CVE-Nummern mit Link zum Original, nicht der Text der Meldung. Die
        Nutzungsbedingungen des BSI erlauben die freie Nutzung nur für nicht kommerzielle Zwecke; wer die Anwendung
        kommerziell betreibt, schaltet den Abruf ab oder holt sich vorher die Zustimmung des BSI.
      </p>
      {status && (
        <dl className="mt-4 grid grid-cols-1 gap-2 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-gray-500">Gespeicherte Meldungen</dt>
            <dd className="font-medium text-gray-900 dark:text-white">{status.advisories}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Letzter vollständiger Abruf</dt>
            <dd className="font-medium text-gray-900 dark:text-white">{formatTime(status.last_sync)}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Abruf</dt>
            <dd className="font-medium text-gray-900 dark:text-white">{status.enabled ? "eingeschaltet" : "abgeschaltet"}</dd>
          </div>
        </dl>
      )}
      <div className="mt-4 flex flex-wrap gap-3">
        <button
          onClick={() => status && toggle(!status.enabled)}
          disabled={busy || !status}
          className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-700"
        >
          {status?.enabled ? "Abruf abschalten" : "Abruf einschalten"}
        </button>
        <button
          onClick={fetchNow}
          disabled={busy || !status?.enabled}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          Jetzt abrufen
        </button>
      </div>
      {note && <p className="mt-3 text-sm text-green-700 dark:text-green-400">{note}</p>}
      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
    </section>
  );
}
