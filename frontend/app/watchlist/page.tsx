"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Plus, Search, ShieldAlert, Trash2, X } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getSeverityBadgeColor } from "@/lib/utils";
import { formatDate } from "@/lib/admin-api";
import { inputClass, secondaryButton, selectClass } from "@/components/admin/Modal";
import {
  watchFetch,
  type CatalogResult,
  type FeedPage,
  type Watch,
  type WatchSummary,
  type WindowSummary,
} from "@/lib/watchlist-api";

const PAGE_SIZE = 20;

const SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: "Kritisch",
  HIGH: "Hoch",
  MEDIUM: "Mittel",
  LOW: "Niedrig",
};

function Tile({ title, data }: { title: string; data: WindowSummary | undefined }) {
  return (
    <Card>
      <CardContent className="p-5">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-gray-500 dark:text-gray-400">
          {title}
        </p>
        <p className="mt-2 text-3xl font-semibold text-gray-900 dark:text-white">{data?.new ?? "–"}</p>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          neue CVEs · {data?.critical ?? 0} kritisch · {data?.high ?? 0} hoch ·{" "}
          <span className={data && data.exploited > 0 ? "font-medium text-red-500" : ""}>
            {data?.exploited ?? 0} ausgenutzt
          </span>
        </p>
      </CardContent>
    </Card>
  );
}

export default function WatchlistPage() {
  const { user, token, isLoading } = useAuth();
  const router = useRouter();

  const [watches, setWatches] = useState<Watch[]>([]);
  const [summary, setSummary] = useState<WatchSummary | null>(null);
  const [feed, setFeed] = useState<FeedPage | null>(null);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CatalogResult | null>(null);
  const [searching, setSearching] = useState(false);

  const [days, setDays] = useState(30);
  const [minSeverity, setMinSeverity] = useState("");
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [page, setPage] = useState(1);

  useEffect(() => {
    if (!isLoading && !user) router.push("/auth");
  }, [user, isLoading, router]);

  const loadWatches = useCallback(async () => {
    if (!token) return;
    try {
      const [list, sum] = await Promise.all([
        watchFetch<Watch[]>(token, ""),
        watchFetch<WatchSummary>(token, "/summary"),
      ]);
      setWatches(list);
      setSummary(sum);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Laden fehlgeschlagen");
    }
  }, [token]);

  const loadFeed = useCallback(async () => {
    if (!token) return;
    const params = new URLSearchParams({
      days: String(days),
      page: String(page),
      page_size: String(PAGE_SIZE),
    });
    if (minSeverity) params.set("min_severity", minSeverity);
    if (exploitedOnly) params.set("exploited_only", "true");
    try {
      setFeed(await watchFetch<FeedPage>(token, `/feed?${params}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Laden fehlgeschlagen");
    }
  }, [token, days, minSeverity, exploitedOnly, page]);

  useEffect(() => {
    loadWatches();
  }, [loadWatches]);

  useEffect(() => {
    loadFeed();
  }, [loadFeed]);

  // Search as you type, after a short pause
  useEffect(() => {
    if (!token) return;
    const term = query.trim();
    if (!term) {
      setResults(null);
      return;
    }
    setSearching(true);
    const timer = setTimeout(async () => {
      try {
        setResults(await watchFetch<CatalogResult>(token, `/catalog?q=${encodeURIComponent(term)}`));
      } catch (e) {
        setError(e instanceof Error ? e.message : "Suche fehlgeschlagen");
      } finally {
        setSearching(false);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [query, token]);

  async function follow(vendor: string, product?: string) {
    if (!token) return;
    setError("");
    try {
      await watchFetch(token, "", { method: "POST", body: { vendor, product: product ?? null } });
      setQuery("");
      setResults(null);
      setPage(1);
      await Promise.all([loadWatches(), loadFeed()]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Hinzufügen fehlgeschlagen");
    }
  }

  async function unfollow(id: number) {
    if (!token) return;
    setError("");
    try {
      await watchFetch(token, `/${id}`, { method: "DELETE" });
      setPage(1);
      await Promise.all([loadWatches(), loadFeed()]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Entfernen fehlgeschlagen");
    }
  }

  if (isLoading || !user || !token) return null;

  const totalPages = feed ? Math.max(1, Math.ceil(feed.total / PAGE_SIZE)) : 1;
  const catalogEmpty = results !== null && results.catalog_size === 0;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <p className="mb-2 flex items-center gap-3 text-xs font-semibold uppercase tracking-[0.15em] text-blue-600 dark:text-blue-400">
          <span className="h-px w-8 bg-gradient-to-r from-blue-600 to-blue-400" />
          Produktauswahl
        </p>
        <h1 className="text-3xl font-semibold text-gray-900 dark:text-white">Meine Produkte</h1>
        <p className="mt-2 max-w-2xl text-gray-600 dark:text-gray-400">
          Wähle die Hersteller und Produkte, die du einsetzt. Lynx zeigt dir, welche neuen Schwachstellen
          sie betreffen.
        </p>
      </div>

      {error && (
        <div role="alert" className="flex items-start justify-between gap-3 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-400">
          <span>{error}</span>
          <button onClick={() => setError("")} aria-label="Meldung schließen">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Tile title="Letzte 24 Stunden" data={summary?.last_24h} />
        <Tile title="Letzte 7 Tage" data={summary?.last_7d} />
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className="space-y-6">
          <Card>
            <CardContent className="space-y-3 p-5">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Produkt hinzufügen</h2>
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                <input
                  className={`${inputClass} pl-9`}
                  placeholder="Hersteller oder Produkt, z. B. fortinet"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  aria-label="Hersteller oder Produkt suchen"
                />
              </div>

              {searching && <p className="text-sm text-gray-500">Suche…</p>}
              {catalogEmpty && (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Der Produktkatalog ist noch leer. Er wird nach dem ersten Datenimport aufgebaut, ein
                  Administrator kann ihn auch von Hand neu aufbauen lassen.
                </p>
              )}
              {results && !catalogEmpty && results.vendors.length + results.products.length === 0 && !searching && (
                <p className="text-sm text-gray-600 dark:text-gray-400">Nichts gefunden.</p>
              )}

              {results && results.vendors.length > 0 && (
                <div>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">Hersteller</p>
                  <ul className="divide-y divide-gray-200 dark:divide-white/10">
                    {results.vendors.map((v) => (
                      <li key={v.vendor} className="flex items-center justify-between gap-3 py-2">
                        <span className="text-sm text-gray-900 dark:text-white">
                          {v.label}
                          <span className="ml-2 text-xs text-gray-500">{v.product_count} Produkte</span>
                        </span>
                        <button
                          className={secondaryButton}
                          disabled={v.watched}
                          onClick={() => follow(v.vendor)}
                          aria-label={`Alle Produkte von ${v.label} folgen`}
                        >
                          <Plus className="h-4 w-4" />
                          {v.watched ? "Gefolgt" : "Alle folgen"}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {results && results.products.length > 0 && (
                <div>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">Produkte</p>
                  <ul className="divide-y divide-gray-200 dark:divide-white/10">
                    {results.products.map((p) => (
                      <li key={`${p.vendor}:${p.product}`} className="flex items-center justify-between gap-3 py-2">
                        <span className="text-sm text-gray-900 dark:text-white">
                          {p.label}
                          <span className="ml-2 text-xs text-gray-500">{p.cve_count} CVEs</span>
                        </span>
                        <button
                          className={secondaryButton}
                          disabled={p.watched}
                          onClick={() => follow(p.vendor, p.product)}
                          aria-label={`${p.label} folgen`}
                        >
                          <Plus className="h-4 w-4" />
                          {p.watched ? "Gefolgt" : "Folgen"}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-5">
              <h2 className="mb-3 text-lg font-semibold text-gray-900 dark:text-white">Gefolgt ({watches.length})</h2>
              {watches.length === 0 ? (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Noch nichts gewählt. Suche oben nach einem Hersteller oder Produkt.
                </p>
              ) : (
                <ul className="divide-y divide-gray-200 dark:divide-white/10">
                  {watches.map((w) => (
                    <li key={w.id} className="flex items-center justify-between gap-3 py-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-gray-900 dark:text-white">{w.label}</p>
                        <p className="text-xs text-gray-500">
                          {w.cves_7d} in 7 Tagen · {w.cves_30d} in 30 Tagen
                        </p>
                      </div>
                      <button
                        onClick={() => unfollow(w.id)}
                        className="rounded-lg p-2 text-gray-500 hover:bg-red-500/10 hover:text-red-500"
                        aria-label={`${w.label} nicht mehr folgen`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardContent className="space-y-4 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Betroffene Schwachstellen</h2>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  className={selectClass}
                  value={days}
                  onChange={(e) => { setDays(Number(e.target.value)); setPage(1); }}
                  aria-label="Zeitraum"
                >
                  <option value={7}>7 Tage</option>
                  <option value={30}>30 Tage</option>
                  <option value={90}>90 Tage</option>
                  <option value={365}>1 Jahr</option>
                </select>
                <select
                  className={selectClass}
                  value={minSeverity}
                  onChange={(e) => { setMinSeverity(e.target.value); setPage(1); }}
                  aria-label="Mindestens"
                >
                  <option value="">Alle Schweregrade</option>
                  <option value="critical">Nur kritisch</option>
                  <option value="high">Hoch und mehr</option>
                  <option value="medium">Mittel und mehr</option>
                </select>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="checkbox"
                    checked={exploitedOnly}
                    onChange={(e) => { setExploitedOnly(e.target.checked); setPage(1); }}
                  />
                  Nur ausgenutzte
                </label>
              </div>
            </div>

            {watches.length === 0 ? (
              <p className="py-8 text-center text-sm text-gray-600 dark:text-gray-400">
                Wähle links ein Produkt, dann erscheinen hier die betroffenen CVEs.
              </p>
            ) : !feed ? (
              <p className="py-8 text-center text-sm text-gray-500">Lade…</p>
            ) : feed.items.length === 0 ? (
              <p className="py-8 text-center text-sm text-gray-600 dark:text-gray-400">
                Keine passenden Schwachstellen in diesem Zeitraum.
              </p>
            ) : (
              <ul className="divide-y divide-gray-200 dark:divide-white/10">
                {feed.items.map((item) => (
                  <li key={item.cve_id} className="py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/vulnerabilities/${item.cve_id}`}
                        className="font-mono text-sm font-medium text-link hover:underline"
                      >
                        {item.cve_id}
                      </Link>
                      {item.severity && (
                        <Badge variant="outline" className={getSeverityBadgeColor(item.severity)}>
                          {SEVERITY_LABEL[item.severity.toUpperCase()] ?? item.severity}
                          {item.cvss_score != null ? ` ${item.cvss_score.toFixed(1)}` : ""}
                        </Badge>
                      )}
                      {item.exploited_in_the_wild && (
                        <Badge variant="outline" className="border-red-500/50 bg-red-500/10 text-red-500">
                          <ShieldAlert className="mr-1 h-3 w-3" /> Ausgenutzt
                        </Badge>
                      )}
                      <span className="ml-auto text-xs text-gray-500">{item.published_at ? formatDate(item.published_at) : "–"}</span>
                    </div>
                    <p className="mt-1 text-sm text-gray-800 dark:text-gray-200">{item.title}</p>
                    <p className="mt-1 text-xs text-gray-500">Betrifft: {item.products.join(", ")}</p>
                  </li>
                ))}
              </ul>
            )}

            {feed && feed.total > PAGE_SIZE && (
              <div className="flex items-center justify-between pt-2 text-sm text-gray-600 dark:text-gray-400">
                <span>
                  {feed.total} Treffer · Seite {page} von {totalPages}
                </span>
                <div className="flex gap-2">
                  <button className={secondaryButton} disabled={page <= 1} onClick={() => setPage(page - 1)}>
                    Zurück
                  </button>
                  <button className={secondaryButton} disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
                    Weiter
                  </button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
