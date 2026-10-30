"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, ExternalLink, Search } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  BSI_SEVERITIES,
  BSI_SEVERITY_CLASS,
  BSI_SOURCE_NOTE,
  fetchBsiPage,
  type BsiPage,
} from "@/lib/bsi-api";

function day(iso: string | null): string {
  if (!iso) return "–";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "–" : d.toLocaleDateString("de-DE");
}

export default function BsiPageView() {
  const [data, setData] = useState<BsiPage | null>(null);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [input, setInput] = useState("");
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // a newer request makes the answer of an older one irrelevant
    const controller = new AbortController();
    setLoading(true);
    fetchBsiPage({ page, severity, q: query }, controller.signal)
      .then((result) => {
        setData(result);
        setError("");
        setLoading(false);
      })
      .catch((e) => {
        if (controller.signal.aborted || e?.name === "AbortError") return;
        setError("Die Warnmeldungen konnten nicht geladen werden.");
        setLoading(false);
      });
    return () => controller.abort();
  }, [page, severity, query]);

  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">BSI CERT-Bund</h1>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Warnmeldungen des Warn- und Informationsdienstes (WID) des Bundesamts für Sicherheit in der
          Informationstechnik, mit den zugehörigen CVE-Nummern. Ein Klick auf die Nummer öffnet die Meldung beim BSI.
        </p>
      </div>

      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          setQuery(input.trim());
        }}
      >
        <label className="text-sm">
          <span className="mb-1 block text-gray-600 dark:text-gray-400">Suche (Titel, Nummer oder CVE)</span>
          <span className="flex">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              maxLength={100}
              className="w-64 max-w-full rounded-l-lg border border-gray-300 bg-white px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
              placeholder="z. B. Windows oder CVE-2026-1234"
            />
            <button
              type="submit"
              className="rounded-r-lg bg-blue-600 px-3 text-white hover:bg-blue-700"
              aria-label="Suchen"
            >
              <Search className="h-4 w-4" />
            </button>
          </span>
        </label>
        <label className="text-sm">
          <span className="mb-1 block text-gray-600 dark:text-gray-400">Einstufung</span>
          <select
            value={severity}
            onChange={(e) => {
              setPage(1);
              setSeverity(e.target.value);
            }}
            className="rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
          >
            <option value="">alle</option>
            {BSI_SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </form>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {data && data.total === 0 && !loading && !error && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-gray-600 dark:text-gray-400">
            Keine Warnmeldungen gefunden. Sind noch keine geladen, holt der Hintergrundjob sie alle drei Stunden; in
            der Administration unter „Daten“ lässt sich der Abruf sofort starten.
          </CardContent>
        </Card>
      )}

      <div className="space-y-3">
        {data?.items.map((a) => (
          <Card key={a.advisory_id}>
            <CardContent className="space-y-2 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <a
                  href={a.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-sm text-link hover:underline"
                >
                  {a.advisory_id}
                  <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                  <span className="sr-only">(öffnet beim BSI)</span>
                </a>
                {a.severity && <Badge className={BSI_SEVERITY_CLASS[a.severity]}>{a.severity}</Badge>}
                <span className="text-xs text-gray-500">
                  veröffentlicht {day(a.published_at)}, geändert {day(a.updated_at)}
                </span>
              </div>
              <p className="font-medium text-gray-900 dark:text-white">{a.title}</p>
              {a.products.length > 0 && (
                <p className="text-sm text-gray-600 dark:text-gray-400">Betrifft: {a.products.join(", ")}</p>
              )}
              {a.cves.length > 0 && (
                <p className="flex flex-wrap gap-1.5 text-xs">
                  {a.cves.map((cve) => (
                    <Link
                      key={cve}
                      href={`/vulnerabilities/${cve}`}
                      className="rounded border border-gray-300 px-1.5 py-0.5 font-mono hover:bg-gray-50 dark:border-gray-600 dark:hover:bg-gray-700"
                    >
                      {cve}
                    </Link>
                  ))}
                  {a.cve_count > a.cves.length && (
                    <span className="py-0.5 text-gray-500">und {a.cve_count - a.cves.length} weitere</span>
                  )}
                </p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {data && data.total > 0 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">
            {data.total} Meldungen, Seite {page} von {pages}
          </span>
          <span className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="inline-flex items-center rounded-lg border border-gray-300 px-3 py-1.5 disabled:opacity-40 dark:border-gray-600"
            >
              <ChevronLeft className="h-4 w-4" aria-hidden /> Zurück
            </button>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages || loading}
              className="inline-flex items-center rounded-lg border border-gray-300 px-3 py-1.5 disabled:opacity-40 dark:border-gray-600"
            >
              Weiter <ChevronRight className="h-4 w-4" aria-hidden />
            </button>
          </span>
        </div>
      )}

      <p className="border-t border-gray-200 pt-4 text-xs text-gray-500 dark:border-gray-700">{BSI_SOURCE_NOTE}</p>
    </div>
  );
}
