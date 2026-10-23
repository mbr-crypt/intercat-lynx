"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, Copy, KeyRound, Trash2 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { formatDate } from "@/lib/admin-api";
import { inputClass, primaryButton, secondaryButton } from "@/components/admin/Modal";
import { tokenFetch, type ApiTokenInfo } from "@/lib/watchlist-api";

export function ApiTokensCard({ token }: { token: string }) {
  const [tokens, setTokens] = useState<ApiTokenInfo[]>([]);
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setTokens(await tokenFetch<ApiTokenInfo[]>(token, ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Laden fehlgeschlagen");
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function create() {
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      const res = await tokenFetch<{ token: string }>(token, "", {
        method: "POST",
        body: { name: name.trim() },
      });
      setFresh(res.token);
      setName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erstellen fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  }

  async function remove(t: ApiTokenInfo) {
    if (!window.confirm(`Token „${t.name}“ löschen? Zabbix verliert damit sofort den Zugriff.`)) return;
    setError("");
    try {
      await tokenFetch(token, `/${t.id}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Löschen fehlgeschlagen");
    }
  }

  async function copy() {
    if (!fresh) return;
    try {
      await navigator.clipboard.writeText(fresh);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* the text stays selectable */
    }
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">API-Zugang (Zabbix)</h2>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            Mit einem Token holt Zabbix die Zahlen zu deinen Produkten ab. Das Token darf nur lesen und nur
            diese Zusammenfassung abrufen, sonst nichts.
          </p>
        </div>

        <div className="flex gap-2">
          <input
            className={inputClass}
            placeholder="Name, z. B. zabbix"
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
            aria-label="Name des Tokens"
          />
          <button className={primaryButton} disabled={busy || !name.trim()} onClick={create}>
            <KeyRound className="h-4 w-4" /> Erstellen
          </button>
        </div>

        {fresh && (
          <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4 text-sm">
            <p className="font-medium text-gray-900 dark:text-white">Dein neues Token</p>
            <p className="mt-1 text-gray-700 dark:text-gray-300">
              Es wird nur jetzt angezeigt. Trage es in Zabbix im Makro <code>{"{$LYNX.TOKEN}"}</code> ein.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <code className="break-all rounded bg-black/20 px-2 py-1">{fresh}</code>
              <button className={secondaryButton} onClick={copy} aria-label="Token kopieren">
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </button>
              <button className={secondaryButton} onClick={() => setFresh(null)}>
                Ausblenden
              </button>
            </div>
          </div>
        )}

        {error && <p role="alert" className="text-sm text-red-500">{error}</p>}

        {tokens.length > 0 && (
          <ul className="divide-y divide-gray-200 dark:divide-white/10">
            {tokens.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 py-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                    {t.name} <code className="ml-1 text-xs text-gray-500">{t.prefix}…</code>
                  </p>
                  <p className="text-xs text-gray-500">
                    erstellt {formatDate(t.created_at)} · {t.last_used_at ? `zuletzt benutzt ${formatDate(t.last_used_at)}` : "noch nie benutzt"}
                  </p>
                </div>
                <button
                  onClick={() => remove(t)}
                  className="rounded-lg p-2 text-gray-500 hover:bg-red-500/10 hover:text-red-500"
                  aria-label={`Token ${t.name} löschen`}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
