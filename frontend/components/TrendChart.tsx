"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent } from "@/components/ui/card";
import { fetchTrend, type TrendBucket, type TrendData, type TrendPeriod } from "@/lib/watchlist-api";

// Bottom to top of the stack. The severest sits on top, where the eye lands first
const SERIES = [
  { key: "unknown", label: "Ohne Wertung", color: "#9ca3af" },
  { key: "low", label: "Niedrig", color: "#3b82f6" },
  { key: "medium", label: "Mittel", color: "#eab308" },
  { key: "high", label: "Hoch", color: "#f97316" },
  { key: "critical", label: "Kritisch", color: "#dc2626" },
] as const;

const PERIODS: { id: TrendPeriod; label: string }[] = [
  { id: "day", label: "Tag" },
  { id: "week", label: "Woche" },
  { id: "month", label: "Monat" },
];

// `phrase` completes "in den letzten ..." (dative)
const RANGES: Record<TrendPeriod, { days: number; label: string; phrase: string }[]> = {
  day: [
    { days: 30, label: "30 Tage", phrase: "30 Tagen" },
    { days: 90, label: "90 Tage", phrase: "90 Tagen" },
    { days: 365, label: "1 Jahr", phrase: "12 Monaten" },
  ],
  week: [
    { days: 182, label: "6 Monate", phrase: "6 Monaten" },
    { days: 365, label: "1 Jahr", phrase: "12 Monaten" },
    { days: 1095, label: "3 Jahre", phrase: "3 Jahren" },
  ],
  month: [
    { days: 365, label: "1 Jahr", phrase: "12 Monaten" },
    { days: 1095, label: "3 Jahre", phrase: "3 Jahren" },
    { days: 1825, label: "5 Jahre", phrase: "5 Jahren" },
    { days: 3650, label: "10 Jahre", phrase: "10 Jahren" },
  ],
};

const DEFAULT_RANGE: Record<TrendPeriod, number> = { day: 90, week: 365, month: 1825 };

const nf = new Intl.NumberFormat("de-DE");

function label(date: string, period: TrendPeriod, long = false): string {
  const d = new Date(`${date}T00:00:00Z`);
  if (period === "month") {
    return d.toLocaleDateString("de-DE", { month: long ? "long" : "short", year: "2-digit", timeZone: "UTC" });
  }
  const text = d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", timeZone: "UTC" });
  return period === "week" ? (long ? `Woche ab ${text}` : text) : text;
}

function change(total: number, previous: number): string | null {
  if (previous === 0) return total === 0 ? null : "vorher keine";
  const pct = Math.round(((total - previous) / previous) * 100);
  return `${pct > 0 ? "+" : ""}${pct} %`;
}

function ChartTooltip({ active, payload, period }: { active?: boolean; payload?: any[]; period: TrendPeriod }) {
  if (!active || !payload?.length) return null;
  const b: TrendBucket = payload[0].payload;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-lg">
      <p className="font-semibold text-gray-900 dark:text-white">
        {label(b.date, period, true)}
        {b.partial && <span className="ml-1 font-normal text-gray-500">(läuft noch)</span>}
      </p>
      <p className="mt-1 text-gray-700 dark:text-gray-300">{nf.format(b.total)} neue CVEs</p>
      <ul className="mt-1 space-y-0.5">
        {[...SERIES].reverse().map((s) =>
          b[s.key] > 0 ? (
            <li key={s.key} className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
              <span className="inline-block h-2 w-2 rounded-sm" style={{ background: s.color }} />
              {s.label}: {nf.format(b[s.key])}
            </li>
          ) : null
        )}
      </ul>
      {b.exploited > 0 && (
        <p className="mt-1 font-medium text-red-500">{nf.format(b.exploited)} aktiv ausgenutzt</p>
      )}
    </div>
  );
}

export function TrendChart({
  title,
  description,
  token,
}: {
  title: string;
  description?: string;
  /** With a token the chart shows the signed-in user's followed products only */
  token?: string | null;
}) {
  const [period, setPeriod] = useState<TrendPeriod>("day");
  const [days, setDays] = useState(DEFAULT_RANGE.day);
  const [data, setData] = useState<TrendData | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [asTable, setAsTable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchTrend(period, days, token)
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setError("");
        }
      })
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : "Laden fehlgeschlagen"))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [period, days, token]);

  function pickPeriod(next: TrendPeriod) {
    setPeriod(next);
    setDays(DEFAULT_RANGE[next]);
  }

  const buckets = data?.buckets ?? [];
  const delta = data ? change(data.total, data.previous_total) : null;
  const tickEvery = useMemo(() => Math.max(0, Math.ceil(buckets.length / 8) - 1), [buckets.length]);
  const rangePhrase = RANGES[period].find((r) => r.days === days)?.phrase ?? `${days} Tagen`;

  const chip = (active: boolean) =>
    `rounded-lg px-3 py-1.5 text-sm transition-colors ${
      active
        ? "bg-blue-600 text-white"
        : "text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-white/10"
    }`;

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
            {description && <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{description}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <div className="flex rounded-lg border border-border p-0.5" role="group" aria-label="Zeitraster">
              {PERIODS.map((p) => (
                <button key={p.id} className={chip(p.id === period)} onClick={() => pickPeriod(p.id)}>
                  {p.label}
                </button>
              ))}
            </div>
            <select
              aria-label="Zeitraum"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="rounded-lg border border-border bg-transparent px-3 py-1.5 text-sm text-gray-700 dark:text-gray-300"
            >
              {RANGES[period].map((r) => (
                <option key={r.days} value={r.days} className="text-black">
                  {r.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {data && (
          <p className="text-sm text-gray-700 dark:text-gray-300">
            <span className="text-2xl font-semibold text-gray-900 dark:text-white">{nf.format(data.total)}</span>{" "}
            neue CVEs in den letzten {rangePhrase}
            {delta && (
              <span className="text-gray-500 dark:text-gray-400"> · {delta} zum Zeitraum davor ({nf.format(data.previous_total)})</span>
            )}
          </p>
        )}

        {error && <p role="alert" className="text-sm text-red-500">{error}</p>}

        {!asTable ? (
          <div className={`h-64 text-gray-500 transition-opacity ${loading ? "opacity-50" : ""}`}>
            {data && data.total === 0 && !loading ? (
              <div className="flex h-full items-center justify-center text-sm">
                {token ? "Keine neuen CVEs zu deinen Produkten in diesem Zeitraum." : "Keine neuen CVEs in diesem Zeitraum."}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={buckets} margin={{ top: 4, right: 4, left: -16, bottom: 0 }}>
                  <CartesianGrid vertical={false} stroke="currentColor" strokeOpacity={0.15} />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(d) => label(d, period)}
                    interval={tickEvery}
                    tickLine={false}
                    axisLine={false}
                    stroke="currentColor"
                    fontSize={12}
                  />
                  <YAxis allowDecimals={false} tickLine={false} axisLine={false} stroke="currentColor" fontSize={12} />
                  <Tooltip content={<ChartTooltip period={period} />} cursor={{ fill: "currentColor", fillOpacity: 0.08 }} />
                  {SERIES.map((s, i) => (
                    <Bar
                      key={s.key}
                      dataKey={s.key}
                      stackId="sev"
                      fill={s.color}
                      stroke="hsl(var(--card))"
                      strokeWidth={buckets.length > 60 ? 0 : 1}
                      radius={i === SERIES.length - 1 ? [3, 3, 0, 0] : 0}
                      isAnimationActive={false}
                    >
                      {buckets.map((b) => (
                        <Cell key={b.date} fillOpacity={b.partial ? 0.55 : 1} />
                      ))}
                    </Bar>
                  ))}
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        ) : (
          <div className="max-h-64 overflow-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-3 py-2">{PERIODS.find((p) => p.id === period)?.label}</th>
                  <th className="px-3 py-2 text-right">Gesamt</th>
                  {[...SERIES].reverse().map((s) => (
                    <th key={s.key} className="px-3 py-2 text-right">{s.label}</th>
                  ))}
                  <th className="px-3 py-2 text-right">Ausgenutzt</th>
                </tr>
              </thead>
              <tbody className="text-gray-800 dark:text-gray-200">
                {[...buckets].reverse().map((b) => (
                  <tr key={b.date} className="border-t border-border">
                    <td className="px-3 py-1.5">{label(b.date, period, true)}{b.partial ? " *" : ""}</td>
                    <td className="px-3 py-1.5 text-right font-medium">{nf.format(b.total)}</td>
                    {[...SERIES].reverse().map((s) => (
                      <td key={s.key} className="px-3 py-1.5 text-right">{nf.format(b[s.key])}</td>
                    ))}
                    <td className="px-3 py-1.5 text-right">{nf.format(b.exploited)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-gray-500 dark:text-gray-400">
          <ul className="flex flex-wrap gap-x-4 gap-y-1" aria-label="Legende">
            {[...SERIES].reverse().map((s) => (
              <li key={s.key} className="flex items-center gap-1.5">
                <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
                {s.label}
              </li>
            ))}
          </ul>
          <div className="flex items-center gap-3">
            <span>Heller Balken: Zeitraum läuft noch</span>
            <button className="underline underline-offset-2 hover:text-gray-800 dark:hover:text-white" onClick={() => setAsTable(!asTable)}>
              {asTable ? "Als Diagramm" : "Als Tabelle"}
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
