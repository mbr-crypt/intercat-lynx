'use client';

import { cloneElement, useCallback, useEffect, useId, useRef, useState } from 'react';
import Link from 'next/link';
import { CheckCircle2, AlertTriangle, XCircle, Loader2 } from 'lucide-react';
import { LynxMark } from '@/components/LynxMark';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { TwoFactorSettings } from '@/components/TwoFactorSettings';
import { IMPORT_DAY_OPTIONS, ImportProgress } from '@/components/ImportProgress';
import type { ImportStatus as AdminImportStatus } from '@/lib/admin-api';

const inputClass =
  'w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary';
const labelClass = 'block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300';

type Step = 'token' | 'checks' | 'admin' | 'twofactor' | 'settings' | 'import' | 'done';
const STEPS: { id: Step; label: string }[] = [
  { id: 'token', label: 'Zugang' },
  { id: 'checks', label: 'Systemprüfung' },
  { id: 'admin', label: 'Root-Benutzer' },
  { id: 'twofactor', label: 'Zwei-Faktor' },
  { id: 'settings', label: 'Einstellungen' },
  { id: 'import', label: 'Daten laden' },
  { id: 'done', label: 'Fertig' },
];

interface Check { name: string; ok: boolean; required: boolean; detail: string }
type ImportStatus = AdminImportStatus;

function errorText(data: any, fallback: string): string {
  if (typeof data?.detail === 'string') return data.detail;
  if (Array.isArray(data?.details) && data.details.length) {
    return data.details.map((d: any) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ');
  }
  return fallback;
}

export default function SetupPage() {
  const [step, setStep] = useState<Step>('token');
  const [setupToken, setSetupToken] = useState('');
  const [adminToken, setAdminToken] = useState<string | null>(null);
  const [adminExists, setAdminExists] = useState(false);
  const [twoFactorOn, setTwoFactorOn] = useState(false);
  const [skipTwoFactor, setSkipTwoFactor] = useState(false);
  const [registrationEnabled, setRegistrationEnabled] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [closed, setClosed] = useState(false);

  // Generic call with the setup token
  const call = useCallback(
    async (method: string, path: string, body?: unknown, token = setupToken) => {
      const res = await fetch(`/api/v1/setup${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', 'X-Setup-Token': token },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    },
    [setupToken],
  );

  // Is the assistant still open at all?
  useEffect(() => {
    fetch('/api/v1/setup/status', { cache: 'no-store' })
      .then((r) => r.json())
      .then((d) => setClosed(!d.setup_required))
      .catch(() => {});
    try {
      const saved = sessionStorage.getItem('lynx_setup_token');
      if (saved) setSetupToken(saved);
    } catch {}
  }, []);

  const verifyToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    const r = await call('POST', '/verify-token');
    setBusy(false);
    if (!r.ok) {
      setError(r.status === 403 ? 'Das Setup-Token ist nicht korrekt.' : errorText(r.data, 'Prüfung fehlgeschlagen'));
      return;
    }
    try { sessionStorage.setItem('lynx_setup_token', setupToken); } catch {}
    setAdminExists(!!r.data.admin_exists);
    setStep('checks');
  };

  if (closed) {
    return (
      <Shell step="done">
        <Card>
          <CardHeader>
            <CardTitle>Die Einrichtung ist abgeschlossen</CardTitle>
            <CardDescription>Der Assistent ist nicht mehr verfügbar.</CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/auth" className="text-link underline">Zur Anmeldung</Link>
          </CardContent>
        </Card>
      </Shell>
    );
  }

  return (
    <Shell step={step}>
      {step === 'token' && (
        <Card>
          <CardHeader>
            <CardTitle>Willkommen bei InterCat Lynx</CardTitle>
            <CardDescription>
              Diese Installation ist noch nicht eingerichtet. Damit nicht ein Fremder die Einrichtung
              übernimmt, brauchst du das <strong>Setup-Token</strong>. Du findest es im Protokoll des
              Servers: <code>docker compose logs backend | grep -A3 &quot;setup token&quot;</code> (oder die
              Umgebungsvariable <code>SETUP_TOKEN</code>).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={verifyToken} className="space-y-4">
              <input
                className={inputClass}
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value.trim())}
                placeholder="Setup-Token"
                autoComplete="off"
                spellCheck={false}
                required
              />
              <ErrorLine text={error} />
              <Button type="submit" disabled={busy || !setupToken}>Weiter</Button>
            </form>
          </CardContent>
        </Card>
      )}

      {step === 'checks' && <ChecksStep call={call} onNext={() => setStep('admin')} />}

      {step === 'admin' && (
        <AdminStep
          call={call}
          adminExists={adminExists}
          onCreated={(token) => { setAdminToken(token); setAdminExists(true); setStep('twofactor'); }}
          onExistingLogin={(token, mfa) => {
            setAdminToken(token);
            setTwoFactorOn(mfa);
            setStep(mfa ? 'settings' : 'twofactor');
          }}
        />
      )}

      {step === 'twofactor' && (
        <Card>
          <CardHeader>
            <CardTitle>Zwei-Faktor-Anmeldung für den Root-Benutzer</CardTitle>
            <CardDescription>
              Der Root-Benutzer darf alles. Deshalb schützen wir ihn doppelt: Passwort <em>und</em> ein
              Code aus einer App auf deinem Handy.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {adminToken ? (
              <TwoFactorSettings token={adminToken} enabled={twoFactorOn} onChanged={() => setTwoFactorOn(true)} />
            ) : (
              <p className="text-sm text-red-600">Keine Sitzung. Bitte zurück zum Root-Benutzer.</p>
            )}
            <div className="flex items-center gap-4 pt-2">
              <Button disabled={!twoFactorOn && !skipTwoFactor} onClick={() => setStep('settings')}>Weiter</Button>
              {!twoFactorOn && (
                <label className="flex items-center gap-2 text-xs text-gray-500">
                  <input type="checkbox" checked={skipTwoFactor} onChange={(e) => setSkipTwoFactor(e.target.checked)} />
                  Ohne zweiten Faktor fortfahren (nicht empfohlen)
                </label>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {step === 'settings' && (
        <SettingsStep
          call={call}
          onSaved={(reg) => { setRegistrationEnabled(reg); setStep('import'); }}
        />
      )}

      {step === 'import' && <ImportStep call={call} onNext={() => setStep('done')} />}

      {step === 'done' && (
        <DoneStep
          call={call}
          twoFactorOn={twoFactorOn}
          registrationEnabled={registrationEnabled}
          acknowledgeNo2fa={skipTwoFactor && !twoFactorOn}
          onDone={() => { try { sessionStorage.removeItem('lynx_setup_token'); } catch {} setClosed(true); }}
        />
      )}
    </Shell>
  );
}

// ---------------------------------------------------------------- layout

function Shell({ step, children }: { step: Step; children: React.ReactNode }) {
  const current = STEPS.findIndex((s) => s.id === step);
  return (
    <div className="min-h-screen flex items-start justify-center pt-4 md:pt-12">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-6">
          <div className="flex justify-center mb-3">
            <LynxMark variant="reticle" className="h-24 w-auto text-gray-900 dark:text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">InterCat Lynx einrichten</h1>
        </div>
        <ol className="flex flex-wrap justify-center gap-x-4 gap-y-1 mb-6 text-xs">
          {STEPS.map((s, i) => (
            <li
              key={s.id}
              className={
                i === current ? 'font-bold text-link' : i < current ? 'text-green-600' : 'text-gray-400'
              }
            >
              {i < current ? '✓ ' : `${i + 1}. `}{s.label}
            </li>
          ))}
        </ol>
        {children}
      </div>
    </div>
  );
}

/** Label that is really tied to its input (click on label, screen readers). */
function Field({ label, children }: { label: string; children: React.ReactElement }) {
  const id = useId();
  return (
    <>
      <label htmlFor={id} className={labelClass}>{label}</label>
      {cloneElement(children, { id })}
    </>
  );
}

function ErrorLine({ text }: { text: string }) {
  return text ? <p className="text-sm text-red-600" role="alert">{text}</p> : null;
}

type Call = (m: string, p: string, b?: unknown, t?: string) => Promise<{ ok: boolean; status: number; data: any }>;

// ---------------------------------------------------------------- steps

function ChecksStep({ call, onNext }: { call: Call; onNext: () => void }) {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [canContinue, setCanContinue] = useState(false);
  const run = useCallback(async () => {
    setChecks(null);
    const r = await call('GET', '/checks');
    if (r.ok) { setChecks(r.data.checks); setCanContinue(r.data.can_continue); }
  }, [call]);
  useEffect(() => { run(); }, [run]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Systemprüfung</CardTitle>
        <CardDescription>Ist alles da, was Lynx zum Laufen braucht?</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {!checks && <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Prüfe…</p>}
        {checks?.map((c) => (
          <div key={c.name} className="flex items-start gap-3 text-sm">
            {c.ok ? <CheckCircle2 className="h-5 w-5 text-green-600 shrink-0" />
              : c.required ? <XCircle className="h-5 w-5 text-red-600 shrink-0" />
              : <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />}
            <div>
              <div className="font-medium text-gray-900 dark:text-white">{c.name}{!c.required && ' (optional)'}</div>
              <div className="text-gray-600 dark:text-gray-400">{c.detail}</div>
            </div>
          </div>
        ))}
        <div className="flex gap-2 pt-2">
          <Button variant="outline" onClick={run}>Erneut prüfen</Button>
          <Button disabled={!canContinue} onClick={onNext}>Weiter</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AdminStep({
  call, adminExists, onCreated, onExistingLogin,
}: {
  call: Call;
  adminExists: boolean;
  onCreated: (token: string) => void;
  onExistingLogin: (token: string, mfa: boolean) => void;
}) {
  const [username, setUsername] = useState('root');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password !== repeat) { setError('Die Passwörter stimmen nicht überein.'); return; }
    setBusy(true);
    const r = await call('POST', '/admin', { username, email, full_name: fullName || null, password });
    setBusy(false);
    if (!r.ok) { setError(errorText(r.data, 'Benutzer konnte nicht angelegt werden')); return; }
    onCreated(r.data.access_token);
  };

  const relogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(errorText(data, 'Anmeldung fehlgeschlagen')); return; }
    onExistingLogin(data.access_token ?? '', !!data.mfa_required);
  };

  if (adminExists) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Root-Benutzer existiert bereits</CardTitle>
          <CardDescription>Melde dich mit ihm an, um die Einrichtung fortzusetzen.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={relogin} className="space-y-4">
            <div><Field label="Benutzername"><input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></Field></div>
            <div><Field label="Passwort"><input type="password" className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></Field></div>
            <ErrorLine text={error} />
            <Button type="submit" disabled={busy}>Anmelden</Button>
          </form>
        </CardContent>
      </Card>
    );
  }

  const tooShort = password.length > 0 && password.length < 12;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Root-Benutzer anlegen</CardTitle>
        <CardDescription>
          Der erste Benutzer bekommt alle Rechte (Administrator). Das Passwort wird nie im Klartext
          gespeichert, sondern als Argon2id-Hash (ein bewusst rechenaufwendiges Verfahren, das Erraten
          teuer macht).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={create} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div><Field label="Benutzername"><input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" minLength={3} required /></Field></div>
            <div><Field label="Name (optional)"><input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} /></Field></div>
          </div>
          <div><Field label="E-Mail-Adresse"><input type="email" className={inputClass} value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required /></Field></div>
          <div><Field label="Passwort (mindestens 12 Zeichen)"><input type="password" className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required /></Field>
            <p className={`text-xs mt-1 ${tooShort ? 'text-red-600' : 'text-gray-500'}`}>
              Länge zählt mehr als Sonderzeichen. Ein Satz aus mehreren Wörtern ist stark und gut zu merken.
            </p></div>
          <div><Field label="Passwort wiederholen"><input type="password" className={inputClass} value={repeat} onChange={(e) => setRepeat(e.target.value)} autoComplete="new-password" required /></Field></div>
          <ErrorLine text={error} />
          <Button type="submit" disabled={busy || password.length < 12}>Root-Benutzer anlegen</Button>
        </form>
      </CardContent>
    </Card>
  );
}

function SettingsStep({ call, onSaved }: { call: Call; onSaved: (registration: boolean) => void }) {
  const [useSmtp, setUseSmtp] = useState(false);
  const [host, setHost] = useState('');
  const [port, setPort] = useState('587');
  const [security, setSecurity] = useState('starttls');
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpPass, setSmtpPass] = useState('');
  const [fromEmail, setFromEmail] = useState('');
  const [fromName, setFromName] = useState('InterCat Lynx');
  const [nvdKey, setNvdKey] = useState('');
  const [registration, setRegistration] = useState(false);
  const [testTo, setTestTo] = useState('');
  const [testResult, setTestResult] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const payload = () => ({
    smtp: useSmtp
      ? { enabled: true, host, port: Number(port), security, username: smtpUser || null,
          password: smtpPass || null, from_email: fromEmail, from_name: fromName }
      : null,
    nvd_api_key: nvdKey || null,
    registration_enabled: registration,
  });

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    const r = await call('PUT', '/settings', payload());
    setBusy(false);
    if (!r.ok) { setError(errorText(r.data, 'Speichern fehlgeschlagen')); return; }
    onSaved(registration);
  };

  const sendTest = async () => {
    setTestResult('');
    setBusy(true);
    const saved = await call('PUT', '/settings', payload());
    if (!saved.ok) { setBusy(false); setTestResult(errorText(saved.data, 'Einstellungen unvollständig')); return; }
    const r = await call('POST', '/smtp-test', { to: testTo });
    setBusy(false);
    setTestResult(r.ok && r.data.ok ? 'Testmail wurde versendet.' : `Fehler: ${r.data.error || errorText(r.data, 'unbekannt')}`);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Einstellungen</CardTitle>
        <CardDescription>Alles optional. Passwörter und Schlüssel werden verschlüsselt gespeichert. Eine Einstellungsseite für später gibt es noch nicht; bis dahin lassen sich die Werte in der Datei .env ändern.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={save} className="space-y-6">
          <fieldset className="space-y-3">
            <legend className="text-sm font-semibold text-gray-900 dark:text-white">E-Mail-Versand (SMTP)</legend>
            <p className="text-xs text-gray-500">Für Benachrichtigungen und Bestätigungs-E-Mails.</p>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={useSmtp} onChange={(e) => setUseSmtp(e.target.checked)} /> E-Mail-Versand einrichten
            </label>
            {useSmtp && (
              <div className="space-y-3">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="sm:col-span-2"><Field label="Server"><input className={inputClass} value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.org" required /></Field></div>
                  <div><Field label="Port"><input className={inputClass} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required /></Field></div>
                </div>
                <div><Field label="Verschlüsselung"><select className={inputClass} value={security} onChange={(e) => { setSecurity(e.target.value); setPort(e.target.value === 'ssl' ? '465' : '587'); }}>
                    <option value="starttls">STARTTLS (Port 587, empfohlen)</option>
                    <option value="ssl">SSL/TLS (Port 465)</option>
                    <option value="none">Keine (nur für interne Testserver)</option>
                  </select></Field></div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div><Field label="Benutzername"><input className={inputClass} value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)} autoComplete="off" /></Field></div>
                  <div><Field label="Passwort"><input type="password" className={inputClass} value={smtpPass} onChange={(e) => setSmtpPass(e.target.value)} autoComplete="new-password" /></Field></div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div><Field label="Absenderadresse"><input type="email" className={inputClass} value={fromEmail} onChange={(e) => setFromEmail(e.target.value)} required /></Field></div>
                  <div><Field label="Absendername"><input className={inputClass} value={fromName} onChange={(e) => setFromName(e.target.value)} /></Field></div>
                </div>
                <div className="flex flex-wrap items-end gap-2">
                  <div className="flex-1 min-w-[12rem]"><Field label="Testmail senden an"><input type="email" className={inputClass} value={testTo} onChange={(e) => setTestTo(e.target.value)} /></Field></div>
                  <Button type="button" variant="outline" disabled={busy || !testTo || !host || !fromEmail} onClick={sendTest}>Test senden</Button>
                </div>
                {testResult && <p className="text-sm text-gray-700 dark:text-gray-300">{testResult}</p>}
              </div>
            )}
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="text-sm font-semibold text-gray-900 dark:text-white">NVD-API-Schlüssel</legend>
            <p className="text-xs text-gray-500">
              Die NVD ist die Schwachstellen-Datenbank des US-Instituts NIST. Ohne Schlüssel lädt Lynx
              langsam (ca. 10 Anfragen pro Minute), mit kostenlosem Schlüssel etwa fünfmal schneller.
              Beantragen: nvd.nist.gov/developers/request-an-api-key
            </p>
            <input className={inputClass} value={nvdKey} onChange={(e) => setNvdKey(e.target.value)} autoComplete="off" spellCheck={false} placeholder="optional" />
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="text-sm font-semibold text-gray-900 dark:text-white">Selbstregistrierung</legend>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={registration} onChange={(e) => setRegistration(e.target.checked)} />
              <span>Besucher dürfen sich selbst ein Konto anlegen. <span className="text-gray-500">
                Empfehlung für interne Nutzung: aus. Dann legt nur ein Administrator Benutzer an.</span></span>
            </label>
          </fieldset>

          <ErrorLine text={error} />
          <Button type="submit" disabled={busy}>Speichern und weiter</Button>
        </form>
      </CardContent>
    </Card>
  );
}

function ImportStep({ call, onNext }: { call: Call; onNext: () => void }) {
  const [mode, setMode] = useState<'recent' | 'full' | 'skip'>('recent');
  const [days, setDays] = useState(1);
  const [status, setStatus] = useState<ImportStatus>({ state: 'idle' });
  const [error, setError] = useState('');
  const [connectionLost, setConnectionLost] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Right after "Import starten" the server may still answer "idle" for a moment
  // (the job writes its first status a split second later). Do not jump back
  // to the form because of that.
  const startedAt = useRef<number | null>(null);
  const receivedAt = useRef<number>(Date.now());
  const failures = useRef(0);

  const poll = useCallback(async () => {
    try {
      const r = await call('GET', '/import/status');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      failures.current = 0;
      setConnectionLost(false);
      const waiting = startedAt.current !== null && Date.now() - startedAt.current < 20000;
      if (r.data.state === 'idle' && waiting) return;
      if (r.data.state !== 'idle') startedAt.current = null;
      receivedAt.current = Date.now();
      setStatus(r.data);
    } catch {
      failures.current += 1;
      if (failures.current >= 3) setConnectionLost(true);
    }
  }, [call]);

  useEffect(() => {
    poll();
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [poll]);

  const running = status.state === 'running';

  useEffect(() => {
    if (running && !timer.current) timer.current = setInterval(poll, 2000);
    if (!running && timer.current) { clearInterval(timer.current); timer.current = null; }
  }, [running, poll]);

  const start = async () => {
    setError('');
    if (mode === 'skip') { onNext(); return; }
    let r;
    try {
      r = await call('POST', '/import', { mode, days });
    } catch {
      setError('Keine Verbindung zum Server. Bitte erneut versuchen.');
      return;
    }
    if (!r.ok) { setError(errorText(r.data, 'Import konnte nicht gestartet werden')); return; }
    startedAt.current = Date.now();
    receivedAt.current = Date.now();
    setStatus({ state: 'running', phase: 'nvd', message: 'Wird gestartet…', elapsed_seconds: 0, seconds_since_heartbeat: 0, log: [] });
    setTimeout(poll, 800);
  };

  const showProgress = running || status.state === 'done' || status.state === 'error' || status.state === 'interrupted';

  return (
    <Card>
      <CardHeader>
        <CardTitle>Daten laden</CardTitle>
        <CardDescription>
          Lynx füllt seine Datenbank mit Schwachstellen (CVEs) aus der NVD und markiert die, die laut CISA
          gerade aktiv ausgenutzt werden. Der Import läuft im Hintergrund, du kannst die Seite offen lassen
          oder später zurückkehren.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!running && status.state !== 'done' && (
          <div className="space-y-2 text-sm">
            <label className="flex items-start gap-2"><input type="radio" className="mt-1" checked={mode === 'recent'} onChange={() => setMode('recent')} />
              <span><strong>Letzte Tage laden</strong> (empfohlen zum Start; gezählt werden alle in dem Zeitraum <em>geänderten</em> CVEs)
                {mode === 'recent' && (
                  <span className="ml-2">Zeitraum:{' '}
                    <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="border rounded px-1 bg-white dark:bg-gray-800">
                      {IMPORT_DAY_OPTIONS.map((o) => <option key={o.days} value={o.days}>{o.days} {o.days === 1 ? 'Tag' : 'Tage'}</option>)}
                    </select>
                    <span className="ml-2 text-gray-500">{IMPORT_DAY_OPTIONS.find((o) => o.days === days)?.hint}</span></span>)}
              </span></label>
            <label className="flex items-start gap-2"><input type="radio" className="mt-1" checked={mode === 'full'} onChange={() => setMode('full')} />
              <span><strong>Kompletter Bestand</strong> (rund 300.000 CVEs; gemessen etwa 160 CVEs pro Minute, das dauert über einen Tag)</span></label>
            <label className="flex items-start gap-2"><input type="radio" className="mt-1" checked={mode === 'skip'} onChange={() => setMode('skip')} />
              <span><strong>Überspringen</strong> (die geplanten Aufgaben holen danach nur neue Änderungen; mehr lässt sich später unter Verwaltung → Daten nachladen)</span></label>
          </div>
        )}

        {showProgress && (
          <ImportProgress status={status} receivedAt={receivedAt.current} connectionLost={connectionLost} />
        )}

        <ErrorLine text={error} />

        <div className="flex gap-2">
          {!running && status.state !== 'done' && (
            <Button onClick={start}>{mode === 'skip' ? 'Überspringen' : status.state === 'idle' ? 'Import starten' : 'Erneut versuchen'}</Button>
          )}
          {(status.state === 'done' || running) && (
            <Button variant={status.state === 'done' ? 'default' : 'outline'} onClick={onNext}>
              {status.state === 'done' ? 'Weiter' : 'Im Hintergrund weiterlaufen lassen und weiter'}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function DoneStep({
  call, twoFactorOn, registrationEnabled, acknowledgeNo2fa, onDone,
}: {
  call: Call; twoFactorOn: boolean; registrationEnabled: boolean; acknowledgeNo2fa: boolean; onDone: () => void;
}) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const complete = async () => {
    setError('');
    setBusy(true);
    const r = await call('POST', '/complete', { acknowledge_no_2fa: acknowledgeNo2fa });
    setBusy(false);
    if (!r.ok) { setError(errorText(r.data, 'Abschluss fehlgeschlagen')); return; }
    onDone();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Fast geschafft</CardTitle>
        <CardDescription>Zusammenfassung. Mit „Einrichtung abschließen“ wird der Assistent dauerhaft gesperrt.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul className="text-sm space-y-1 text-gray-700 dark:text-gray-300">
          <li>✓ Root-Benutzer angelegt (Passwort als Argon2id gespeichert)</li>
          <li>{twoFactorOn ? '✓ Zwei-Faktor-Anmeldung aktiv' : '⚠ Zwei-Faktor-Anmeldung nicht aktiv'}</li>
          <li>{registrationEnabled ? '• Selbstregistrierung: erlaubt' : '• Selbstregistrierung: gesperrt'}</li>
        </ul>
        <ErrorLine text={error} />
        <Button onClick={complete} disabled={busy}>Einrichtung abschließen</Button>
      </CardContent>
    </Card>
  );
}
