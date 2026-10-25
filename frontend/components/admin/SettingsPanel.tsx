"use client";

/**
 * "Einstellungen" tab of the administration: mail server (SMTP) with test mail,
 * NVD API key, registration and public address, appearance (branding).
 *
 * Every card saves its own part. Passwords and keys are never shown again; the page only
 * knows whether one is set. Where a value comes from (this page, the .env file or the
 * default) is shown, because the database wins over the .env file.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  adminFetch,
  MAX_LOGO_BYTES,
  uploadLogo,
  type AdminSettings,
} from "@/lib/admin-api";
import { inputClass, primaryButton, secondaryButton } from "./Modal";

type Source = "db" | "env" | "default";
type Update = (patch: Record<string, unknown>) => Promise<boolean>;

const SOURCE_TEXT: Record<Source, string> = {
  db: "Wert von dieser Seite",
  env: "Wert aus der .env-Datei (wird von einem Eintrag hier überschrieben)",
  default: "Noch nichts eingetragen",
};

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">{hint}</span>}
    </label>
  );
}

function Card({
  title,
  intro,
  children,
}: {
  title: string;
  intro?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl bg-white p-6 dark:bg-gray-800">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
      {intro && <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{intro}</p>}
      <div className="mt-4 space-y-4">{children}</div>
    </section>
  );
}

function Message({ error, ok }: { error?: string; ok?: string }) {
  if (error)
    return (
      <p role="alert" className="text-sm text-red-600 dark:text-red-400">
        {error}
      </p>
    );
  if (ok)
    return (
      <p role="status" className="text-sm text-green-700 dark:text-green-400">
        {ok}
      </p>
    );
  return null;
}

/** Runs a save and keeps the message for the card. */
function useSave(update: Update) {
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);
  const run = async (patch: Record<string, unknown>, message = "Gespeichert.") => {
    setError("");
    setOk("");
    setBusy(true);
    try {
      const saved = await update(patch);
      if (saved) setOk(message);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Speichern fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  };
  return { run, error, ok, busy, setError, setOk };
}

// --------------------------------------------------------------------------
// mail server
// --------------------------------------------------------------------------

function SmtpCard({ token, settings, update }: { token: string; settings: AdminSettings; update: Update }) {
  const s = settings.smtp;
  // A server that was never set up starts switched on: whoever fills in a host wants to send
  const [enabled, setEnabled] = useState(s.enabled || !s.host);
  const [host, setHost] = useState(s.host);
  const [port, setPort] = useState(String(s.port));
  const [security, setSecurity] = useState<string>(s.security);
  const [username, setUsername] = useState(s.username);
  const [password, setPassword] = useState("");
  const [clearPassword, setClearPassword] = useState(false);
  const [fromEmail, setFromEmail] = useState(s.from_email);
  const [fromName, setFromName] = useState(s.from_name);
  const [testTo, setTestTo] = useState("");
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const save = useSave(update);

  const payload = () => ({
    smtp: {
      enabled,
      host,
      port: Number(port),
      security,
      username: username || null,
      password: password || null,
      from_email: fromEmail,
      from_name: fromName,
    },
    clear_smtp_password: clearPassword && !password,
  });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    await save.run(payload());
    setPassword("");
    setClearPassword(false);
  };

  const sendTest = async () => {
    setTestResult(null);
    setTesting(true);
    try {
      // Test with exactly what is on the page: save first, then send
      await update(payload());
      setPassword("");
      setClearPassword(false);
      const r = await adminFetch<{ ok: boolean; error: string | null }>(token, "/settings/smtp-test", {
        method: "POST",
        body: { to: testTo },
      });
      setTestResult(
        r.ok
          ? { ok: true, text: "Die Testmail wurde versendet. Bitte im Postfach nachsehen." }
          : { ok: false, text: `Der Versand ist fehlgeschlagen: ${r.error ?? "unbekannter Fehler"}` }
      );
    } catch (e) {
      setTestResult({ ok: false, text: e instanceof Error ? e.message : "Test fehlgeschlagen" });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card
      title="E-Mail-Versand (SMTP)"
      intro="Für Bestätigungs-E-Mails, Benachrichtigungen und Produktwarnungen. SMTP ist das übliche Protokoll, mit dem Programme E-Mails über einen Mailserver versenden."
    >
      <form onSubmit={submit} className="space-y-4">
        <p className="text-xs text-gray-500 dark:text-gray-400">{SOURCE_TEXT[s.source]}</p>
        <label className="flex items-center gap-2 text-sm text-gray-900 dark:text-white">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          E-Mail-Versand eingeschaltet
        </label>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <Field label="Server">
              <input className={inputClass} value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.org" required />
            </Field>
          </div>
          <Field label="Port">
            <input className={inputClass} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required />
          </Field>
        </div>
        <Field label="Verschlüsselung" hint="STARTTLS und SSL/TLS verschlüsseln die Verbindung zum Mailserver. „Keine“ nur für interne Testserver.">
          <select
            className={inputClass}
            value={security}
            onChange={(e) => {
              setSecurity(e.target.value);
              setPort(e.target.value === "ssl" ? "465" : e.target.value === "starttls" ? "587" : port);
            }}
          >
            <option value="starttls">STARTTLS (Port 587, empfohlen)</option>
            <option value="ssl">SSL/TLS (Port 465)</option>
            <option value="none">Keine</option>
          </select>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Benutzername">
            <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
          </Field>
          <Field
            label="Passwort"
            hint={s.password_set ? "Ein Passwort ist gespeichert. Leer lassen, um es zu behalten." : "Noch kein Passwort gespeichert."}
          >
            <input
              type="password"
              className={inputClass}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              placeholder={s.password_set ? "••••••••" : ""}
            />
          </Field>
        </div>
        {s.password_set && (
          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input type="checkbox" checked={clearPassword} onChange={(e) => setClearPassword(e.target.checked)} />
            Gespeichertes Passwort löschen
          </label>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Absenderadresse">
            <input type="email" className={inputClass} value={fromEmail} onChange={(e) => setFromEmail(e.target.value)} required />
          </Field>
          <Field label="Absendername">
            <input className={inputClass} value={fromName} onChange={(e) => setFromName(e.target.value)} />
          </Field>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" className={primaryButton} disabled={save.busy || testing}>
            Speichern
          </button>
          <Message error={save.error} ok={save.ok} />
        </div>
      </form>

      <div className="border-t border-gray-200 pt-4 dark:border-gray-700">
        <p className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">Testmail</p>
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[14rem] flex-1">
            <input
              type="email"
              className={inputClass}
              value={testTo}
              onChange={(e) => setTestTo(e.target.value)}
              placeholder="Empfängeradresse"
              aria-label="Empfänger der Testmail"
            />
          </div>
          <button
            type="button"
            className={secondaryButton}
            disabled={testing || save.busy || !testTo || !host || !fromEmail}
            onClick={sendTest}
          >
            {testing ? "Sende …" : "Speichern und Testmail senden"}
          </button>
        </div>
        {testResult && <Message error={testResult.ok ? undefined : testResult.text} ok={testResult.ok ? testResult.text : undefined} />}
      </div>
    </Card>
  );
}

// --------------------------------------------------------------------------
// NVD key
// --------------------------------------------------------------------------

function NvdCard({ settings, update }: { settings: AdminSettings; update: Update }) {
  const [key, setKey] = useState("");
  const save = useSave(update);
  const isSet = settings.nvd.api_key_set;

  return (
    <Card
      title="NVD-API-Schlüssel"
      intro={
        <>
          Die NVD (National Vulnerability Database) ist die Datenquelle für CVEs. Mit einem kostenlosen Schlüssel (bei der NVD
          anzufordern) darf der Import deutlich öfter abfragen. Der Schlüssel gilt ab dem nächsten gestarteten Import.
        </>
      }
    >
      <p className="text-xs text-gray-500 dark:text-gray-400">
        {isSet
          ? settings.nvd.source === "env"
            ? "Ein Schlüssel ist in der .env-Datei gesetzt."
            : "Ein Schlüssel ist gespeichert."
          : "Es ist kein Schlüssel gesetzt."}
      </p>
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          await save.run({ nvd_api_key: key }, key ? "Schlüssel gespeichert." : "Schlüssel entfernt.");
          setKey("");
        }}
      >
        <div className="min-w-[16rem] flex-1">
          <Field label={isSet ? "Neuer Schlüssel" : "Schlüssel"}>
            <input
              type="password"
              className={inputClass}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoComplete="off"
              placeholder={isSet ? "••••••••" : ""}
            />
          </Field>
        </div>
        <button type="submit" className={primaryButton} disabled={save.busy || !key}>
          Speichern
        </button>
        {settings.nvd.source === "db" && (
          <button
            type="button"
            className={secondaryButton}
            disabled={save.busy}
            onClick={() => save.run({ nvd_api_key: "" }, "Schlüssel entfernt.")}
          >
            Schlüssel entfernen
          </button>
        )}
      </form>
      <Message error={save.error} ok={save.ok} />
    </Card>
  );
}

// --------------------------------------------------------------------------
// registration and public address
// --------------------------------------------------------------------------

function AccessCard({ settings, update }: { settings: AdminSettings; update: Update }) {
  const [registration, setRegistration] = useState(settings.registration_enabled);
  const [url, setUrl] = useState(settings.public_url);
  const save = useSave(update);
  // Show what the server stored (it removes a trailing slash)
  useEffect(() => setUrl(settings.public_url), [settings.public_url]);

  return (
    <Card title="Zugang und Adresse">
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          await save.run({ registration_enabled: registration, public_url: url });
        }}
      >
        <label className="flex items-start gap-2 text-sm text-gray-900 dark:text-white">
          <input type="checkbox" className="mt-1" checked={registration} onChange={(e) => setRegistration(e.target.checked)} />
          <span>
            Selbstregistrierung erlauben
            <span className="block text-xs text-gray-500 dark:text-gray-400">
              Ist sie aus, können nur Administratoren Benutzer anlegen (Registerkarte „Benutzer“). Wirkt sofort.
            </span>
          </span>
        </label>
        <Field
          label="Öffentliche Adresse"
          hint={`Mit dieser Adresse beginnen Links in E-Mails und Warnungen, zum Beispiel https://lynx.example.org (ohne Pfad). ${SOURCE_TEXT[settings.public_url_source]}.`}
        >
          <input className={inputClass} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://lynx.example.org" inputMode="url" />
        </Field>
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" className={primaryButton} disabled={save.busy}>
            Speichern
          </button>
          <Message error={save.error} ok={save.ok} />
        </div>
      </form>
    </Card>
  );
}

// --------------------------------------------------------------------------
// appearance
// --------------------------------------------------------------------------

/** Same calculation as the server (WCAG contrast of white text on the colour). */
function contrastWithWhite(hex: string): number {
  const ch = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 1.05 / (0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2] + 0.05);
}

const HEX = /^#[0-9a-fA-F]{6}$/;

function LogoSlot({
  token,
  variant,
  title,
  hint,
  url,
  onChanged,
}: {
  token: string;
  variant: "light" | "dark";
  title: string;
  hint: string;
  url: string | null;
  onChanged: (s: AdminSettings) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const pick = async (file: File | undefined) => {
    if (!file) return;
    setError("");
    if (file.size > MAX_LOGO_BYTES) {
      setError(`Die Datei ist zu groß (höchstens ${MAX_LOGO_BYTES / 1024} KB).`);
      return;
    }
    setBusy(true);
    try {
      onChanged(await uploadLogo(token, variant, file));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Hochladen fehlgeschlagen");
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };

  const remove = async () => {
    setError("");
    setBusy(true);
    try {
      onChanged(await adminFetch<AdminSettings>(token, `/settings/branding/logo/${variant}`, { method: "DELETE" }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Entfernen fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-gray-200 p-3 dark:border-gray-700">
      <p className="text-sm font-medium text-gray-900 dark:text-white">{title}</p>
      <p className="mb-2 text-xs text-gray-500 dark:text-gray-400">{hint}</p>
      <div
        className={`flex h-20 items-center justify-center rounded-lg ${variant === "dark" ? "bg-[#131416]" : "bg-white ring-1 ring-gray-200"}`}
      >
        {url ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={url} alt={`Vorschau: ${title}`} className="max-h-16 max-w-full object-contain" />
        ) : (
          <span className="text-xs text-gray-400">Kein eigenes Logo</span>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input
          ref={input}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          className="sr-only"
          id={`logo-${variant}`}
          onChange={(e) => pick(e.target.files?.[0])}
        />
        <label htmlFor={`logo-${variant}`} className={`${secondaryButton} cursor-pointer ${busy ? "pointer-events-none opacity-50" : ""}`}>
          {url ? "Ersetzen" : "Hochladen"}
        </label>
        {url && (
          <button type="button" className={secondaryButton} onClick={remove} disabled={busy}>
            Entfernen
          </button>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-2 text-xs text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

function BrandingCard({
  token,
  settings,
  update,
  replace,
}: {
  token: string;
  settings: AdminSettings;
  update: Update;
  replace: (s: AdminSettings) => void;
}) {
  const b = settings.branding;
  const [name, setName] = useState(b.name_is_default ? "" : b.name);
  const [accent, setAccent] = useState(b.accent);
  const [footer, setFooter] = useState(b.footer_text);
  const [url, setUrl] = useState(b.url);
  const save = useSave(update);
  // Show what the server stored (trimmed name, lower-case colour)
  useEffect(() => {
    setName(b.name_is_default ? "" : b.name);
    setAccent(b.accent);
  }, [b.name, b.name_is_default, b.accent]);

  const accentValid = accent === "" || HEX.test(accent);
  const ratio = HEX.test(accent) ? contrastWithWhite(accent) : null;
  const tooLight = ratio !== null && ratio < 4.5;

  return (
    <Card
      title="Darstellung"
      intro={
        <>
          Name, Logo und Farbe der Oberfläche, zum Beispiel für eine Instanz in einer Firma. Leere Felder bedeuten: Standard
          ({b.default_name}). Der Link zum Quellcode und der Hinweis „Fork von OpenThreat“ bleiben immer sichtbar, das verlangt die
          Lizenz (AGPL-3.0).
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          await save.run(
            { branding: { name, accent, footer_text: footer, url } },
            "Gespeichert. Die Seiten zeigen es nach wenigen Sekunden (Strg+F5, falls nicht)."
          );
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Produktname" hint={`Kopfzeile, Fußzeile und Seitentitel. Höchstens 40 Zeichen. Standard: ${b.default_name}`}>
            <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} maxLength={40} placeholder={b.default_name} />
          </Field>
          <Field
            label="Akzentfarbe"
            hint="Schaltflächen, Links und aktive Reiter. Die Farbe muss dunkel genug für weiße Schrift sein."
          >
            <div className="flex items-center gap-2">
              <input
                type="color"
                aria-label="Farbe wählen"
                className="h-10 w-12 cursor-pointer rounded border border-gray-300 bg-white p-1 dark:border-gray-600 dark:bg-gray-900"
                value={HEX.test(accent) ? accent : "#2271b3"}
                onChange={(e) => setAccent(e.target.value)}
              />
              <input
                className={inputClass}
                value={accent}
                onChange={(e) => setAccent(e.target.value.trim())}
                placeholder="#2271b3 (Standard)"
                maxLength={7}
                aria-invalid={!accentValid || tooLight}
              />
              {accent && (
                <button type="button" className={secondaryButton} onClick={() => setAccent("")}>
                  Standard
                </button>
              )}
            </div>
            {!accentValid && <span className="mt-1 block text-xs text-red-600 dark:text-red-400">Bitte als #RRGGBB angeben.</span>}
            {tooLight && (
              <span className="mt-1 block text-xs text-red-600 dark:text-red-400">
                Zu hell für weiße Schrift (Kontrast {ratio!.toFixed(1)}:1, nötig 4,5:1).
              </span>
            )}
          </Field>
        </div>

        {HEX.test(accent) && !tooLight && (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-gray-500 dark:text-gray-400">Vorschau:</span>
            <span className="rounded-lg px-4 py-2 font-medium text-white" style={{ backgroundColor: accent }}>
              Schaltfläche
            </span>
          </div>
        )}

        <Field label="Fußzeilentext" hint="Ein kurzer Satz unter dem Logo, zum Beispiel ein Hinweis zur internen Nutzung. Höchstens 200 Zeichen.">
          <input className={inputClass} value={footer} onChange={(e) => setFooter(e.target.value)} maxLength={200} />
        </Field>
        <Field label="Link des Logos (optional)" hint="Wohin ein Klick auf das Logo in der Fußzeile führt, zum Beispiel https://intranet.example.org">
          <input className={inputClass} value={url} onChange={(e) => setUrl(e.target.value)} inputMode="url" placeholder="https://" />
        </Field>

        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" className={primaryButton} disabled={save.busy || !accentValid || tooLight}>
            Speichern
          </button>
          <Message error={save.error} ok={save.ok} />
        </div>
      </form>

      <div className="border-t border-gray-200 pt-4 dark:border-gray-700">
        <p className="mb-1 text-sm font-medium text-gray-900 dark:text-white">Logo</p>
        <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
          PNG, JPEG oder WebP, höchstens 512 KB (kein SVG, weil darin Skripte stehen können). Wird nur ein Logo hochgeladen, gilt es für
          beide Darstellungen. Ein Logo ersetzt in der Kopfzeile Zeichen und Namen. Sichtbar nach wenigen Sekunden (Strg+F5, falls nicht).
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <LogoSlot
            token={token}
            variant="light"
            title="Für die helle Darstellung"
            hint="Dunkles Logo für weißen Hintergrund"
            url={b.has_logo_light ? b.logo_light : null}
            onChanged={replace}
          />
          <LogoSlot
            token={token}
            variant="dark"
            title="Für die dunkle Darstellung"
            hint="Helles Logo für dunklen Hintergrund"
            url={b.has_logo_dark ? b.logo_dark : null}
            onChanged={replace}
          />
        </div>
      </div>
    </Card>
  );
}

// --------------------------------------------------------------------------
// page
// --------------------------------------------------------------------------

export function SettingsPanel({ token }: { token: string }) {
  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setSettings(await adminFetch<AdminSettings>(token, "/settings"));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Einstellungen konnten nicht geladen werden");
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  /** Save a part; the answer replaces the page state (secrets stay hidden). */
  const update: Update = useCallback(
    async (patch) => {
      const next = await adminFetch<AdminSettings>(token, "/settings", { method: "PUT", body: patch });
      setSettings(next);
      return true;
    },
    [token]
  );

  if (error && !settings) {
    return (
      <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
        {error}
      </p>
    );
  }
  if (!settings) return <p className="text-sm text-gray-500">Lade Einstellungen …</p>;

  return (
    <div className="space-y-6">
      <SmtpCard token={token} settings={settings} update={update} />
      <NvdCard settings={settings} update={update} />
      <AccessCard settings={settings} update={update} />
      <BrandingCard token={token} settings={settings} update={update} replace={setSettings} />
    </div>
  );
}
