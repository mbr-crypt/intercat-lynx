"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, Copy, KeyRound, Send } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { formatDate } from "@/lib/admin-api";
import { inputClass, primaryButton, secondaryButton, selectClass } from "@/components/admin/Modal";
import {
  notifyFetch,
  type NotificationSettings,
  type NotificationSettingsPatch,
} from "@/lib/watchlist-api";

function Toggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  hint?: React.ReactNode;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-3">
      <input
        type="checkbox"
        className="mt-1 h-4 w-4 shrink-0"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="block text-sm font-medium text-gray-900 dark:text-white">{label}</span>
        {hint && <span className="block text-xs text-gray-600 dark:text-gray-400">{hint}</span>}
      </span>
    </label>
  );
}

function Status({ ok, error }: { ok: string | null; error: string | null }) {
  if (error) return <p className="text-xs text-red-500">Letzter Versuch fehlgeschlagen: {error}</p>;
  if (ok) return <p className="text-xs text-gray-500">Zuletzt gesendet: {formatDate(ok)}</p>;
  return null;
}

export function NotificationSettingsCard({ token }: { token: string }) {
  const [s, setS] = useState<NotificationSettings | null>(null);
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await notifyFetch<NotificationSettings>(token, "");
      setS(data);
      setUrl(data.webhook_url ?? "");
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : "Laden fehlgeschlagen" });
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function save(patch: NotificationSettingsPatch) {
    setBusy(true);
    setMessage(null);
    try {
      const data = await notifyFetch<NotificationSettings>(token, "", { method: "PUT", body: patch });
      setS(data);
      setUrl(data.webhook_url ?? "");
      if (data.new_webhook_secret) setSecret(data.new_webhook_secret);
      setMessage({ ok: true, text: "Gespeichert." });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : "Speichern fehlgeschlagen" });
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function renewSecret() {
    if (!window.confirm("Das alte Geheimnis wird sofort ungültig. Der Empfänger muss das neue eintragen. Fortfahren?")) return;
    setBusy(true);
    try {
      const res = await notifyFetch<{ secret: string }>(token, "/webhook/secret", { method: "POST" });
      setSecret(res.secret);
      await load();
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : "Fehlgeschlagen" });
    } finally {
      setBusy(false);
    }
  }

  async function sendTest(channel: "email" | "webhook") {
    setBusy(true);
    setMessage(null);
    try {
      const res = await notifyFetch<{ ok: boolean; error: string | null }>(token, `/test/${channel}`, {
        method: "POST",
      });
      setMessage({
        ok: res.ok,
        text: res.ok ? "Testnachricht gesendet." : `Test fehlgeschlagen: ${res.error ?? "unbekannter Fehler"}`,
      });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : "Test fehlgeschlagen" });
    } finally {
      setBusy(false);
    }
  }

  async function copySecret() {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* the user can still select the text */
    }
  }

  if (!s) return null;

  return (
    <Card>
      <CardContent className="space-y-5 p-5">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Benachrichtigungen</h2>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            Du wirst benachrichtigt, wenn Lynx eine neue Schwachstelle für ein gefolgtes Produkt kennt. Ältere
            CVEs werden nicht nachgemeldet.
          </p>
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <label className="text-sm text-gray-700 dark:text-gray-300">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500">
              Mindest-Schweregrad
            </span>
            <select
              className={selectClass}
              value={s.min_severity}
              disabled={busy}
              onChange={(e) => save({ min_severity: e.target.value })}
            >
              <option value="CRITICAL">Kritisch</option>
              <option value="HIGH">Hoch und mehr</option>
              <option value="MEDIUM">Mittel und mehr</option>
              <option value="LOW">Alle</option>
            </select>
          </label>
          <Toggle
            checked={s.always_exploited}
            onChange={(v) => save({ always_exploited: v })}
            label="Aktiv ausgenutzte immer melden"
            hint="auch unterhalb des Mindest-Schweregrads (CISA KEV)"
          />
        </div>

        <div className="space-y-4 border-t border-gray-200 pt-4 dark:border-white/10">
          <Toggle
            checked={s.in_app_enabled}
            onChange={(v) => save({ in_app_enabled: v })}
            label="In Lynx (Glocke oben rechts)"
          />

          <div className="space-y-2">
            <Toggle
              checked={s.email_enabled}
              onChange={(v) => save({ email_enabled: v })}
              label="Per E-Mail"
              hint={
                s.smtp_configured
                  ? `an ${s.email_address}`
                  : "Auf diesem Server ist kein E-Mail-Versand eingerichtet, es kommt nichts an."
              }
            />
            {s.email_enabled && (
              <div className="ml-7 space-y-2">
                <button className={secondaryButton} disabled={busy} onClick={() => sendTest("email")}>
                  <Send className="h-4 w-4" /> Test senden
                </button>
                <Status ok={s.last_email_ok_at} error={s.last_email_error} />
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Toggle
              checked={s.webhook_enabled}
              onChange={(v) => save({ webhook_enabled: v })}
              label="Per Webhook"
              hint="Lynx schickt die Meldungen als signierte JSON-Anfrage an deine Adresse (z. B. Zabbix, Teams, Chat)."
            />
            <div className="ml-7 space-y-2">
              <div className="flex gap-2">
                <input
                  className={inputClass}
                  type="url"
                  placeholder="https://…"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  aria-label="Webhook-Adresse"
                />
                <button
                  className={primaryButton}
                  disabled={busy || url === (s.webhook_url ?? "")}
                  onClick={() => save({ webhook_url: url })}
                >
                  Speichern
                </button>
              </div>
              {s.webhook_enabled && (
                <div className="flex flex-wrap gap-2">
                  <button className={secondaryButton} disabled={busy} onClick={() => sendTest("webhook")}>
                    <Send className="h-4 w-4" /> Test senden
                  </button>
                  <button className={secondaryButton} disabled={busy} onClick={renewSecret}>
                    <KeyRound className="h-4 w-4" /> Neues Geheimnis
                  </button>
                </div>
              )}
              <Status ok={s.last_webhook_ok_at} error={s.last_webhook_error} />
            </div>
          </div>
        </div>

        {secret && (
          <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4 text-sm">
            <p className="font-medium text-gray-900 dark:text-white">Geheimnis für die Signatur</p>
            <p className="mt-1 text-gray-700 dark:text-gray-300">
              Es wird nur jetzt angezeigt. Trage es beim Empfänger ein, damit er prüfen kann, dass die Anfrage von
              Lynx kommt (Kopfzeile <code>X-Lynx-Signature</code>, HMAC-SHA256 über Zeitstempel + „.“ + Inhalt).
            </p>
            <div className="mt-2 flex items-center gap-2">
              <code className="break-all rounded bg-black/20 px-2 py-1">{secret}</code>
              <button className={secondaryButton} onClick={copySecret} aria-label="Geheimnis kopieren">
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </button>
              <button className={secondaryButton} onClick={() => setSecret(null)}>
                Ausblenden
              </button>
            </div>
          </div>
        )}

        {message && (
          <p role="status" className={`text-sm ${message.ok ? "text-green-500" : "text-red-500"}`}>
            {message.text}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
