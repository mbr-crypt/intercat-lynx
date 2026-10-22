'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';

const inputClass =
  'w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary';

interface Props {
  /** Access token of the logged-in user */
  token: string;
  /** Is 2FA currently active for this account? */
  enabled: boolean;
  /** Called after 2FA was switched on or off */
  onChanged?: () => void;
}

async function post(path: string, token: string, body: unknown) {
  const res = await fetch(`/api/v1/auth${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : 'Aktion fehlgeschlagen';
    throw new Error(detail);
  }
  return data;
}

/**
 * Switch two-factor authentication on/off and show the one-time recovery codes.
 * The QR code is shown as an <img> with a data URL, so the SVG can never run scripts.
 */
export function TwoFactorSettings({ token, enabled, onChanged }: Props) {
  const [password, setPassword] = useState('');
  const [setup, setSetup] = useState<{ secret: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [disabling, setDisabling] = useState(false);

  const run = async (fn: () => Promise<void>) => {
    setError('');
    setBusy(true);
    try {
      await fn();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const startSetup = () =>
    run(async () => {
      const data = await post('/2fa/setup', token, { password });
      setSetup({ secret: data.secret, qr_svg: data.qr_svg });
      setPassword('');
    });

  const confirm = () =>
    run(async () => {
      const data = await post('/2fa/enable', token, { code });
      setRecovery(data.recovery_codes);
      setSetup(null);
      setCode('');
      onChanged?.();
    });

  const disable = () =>
    run(async () => {
      await post('/2fa/disable', token, { password, code });
      setPassword('');
      setCode('');
      setDisabling(false);
      onChanged?.();
    });

  const downloadCodes = () => {
    if (!recovery) return;
    const blob = new Blob(
      [`InterCat Lynx - Wiederherstellungscodes\n\n${recovery.join('\n')}\n\nJeder Code gilt nur einmal.\n`],
      { type: 'text/plain' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'lynx-wiederherstellungscodes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  // 1) freshly enabled: show recovery codes exactly once
  if (recovery) {
    return (
      <div className="space-y-3">
        <p className="text-sm font-medium text-green-700 dark:text-green-400">
          Zwei-Faktor-Anmeldung ist aktiv.
        </p>
        <p className="text-sm text-gray-700 dark:text-gray-300">
          Bewahre diese Wiederherstellungscodes sicher auf (Passwortmanager oder ausgedruckt). Mit ihnen
          kommst du ins Konto, wenn das Handy fehlt. <strong>Sie werden nur jetzt angezeigt.</strong>
        </p>
        <div className="grid grid-cols-2 gap-2 font-mono text-sm bg-gray-100 dark:bg-gray-900 rounded p-3">
          {recovery.map((c) => (
            <span key={c}>{c}</span>
          ))}
        </div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={downloadCodes}>
            Als Datei speichern
          </Button>
          <Button type="button" onClick={() => setRecovery(null)}>
            Ich habe sie gesichert
          </Button>
        </div>
      </div>
    );
  }

  // 2) setup in progress: QR code + confirmation code
  if (setup) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-gray-700 dark:text-gray-300">
          Scanne den QR-Code mit einer Authenticator-App (z. B. Microsoft Authenticator, Google
          Authenticator, Aegis, Bitwarden) und gib danach den angezeigten sechsstelligen Code ein.
        </p>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          alt="QR-Code für die Authenticator-App"
          className="bg-white p-2 rounded w-48 h-48"
          src={`data:image/svg+xml;utf8,${encodeURIComponent(setup.qr_svg)}`}
        />
        <p className="text-xs text-gray-500">
          Kein Scan möglich? Schlüssel manuell eintragen:{' '}
          <code className="break-all">{setup.secret}</code>
        </p>
        <input
          className={inputClass + ' text-center tracking-widest'}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
        />
        {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
        <Button type="button" onClick={confirm} disabled={busy || code.trim().length < 6}>
          Bestätigen und aktivieren
        </Button>
      </div>
    );
  }

  // 3) already on
  if (enabled) {
    return (
      <div className="space-y-3">
        <p className="text-sm font-medium text-green-700 dark:text-green-400">
          Zwei-Faktor-Anmeldung ist aktiv.
        </p>
        {!disabling ? (
          <Button type="button" variant="outline" onClick={() => setDisabling(true)}>
            Ausschalten…
          </Button>
        ) : (
          <div className="space-y-2">
            <input
              type="password"
              className={inputClass}
              placeholder="Passwort"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
            <input
              className={inputClass}
              placeholder="Code aus der App oder Wiederherstellungscode"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
            />
            {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
            <div className="flex gap-2">
              <Button type="button" variant="destructive" onClick={disable} disabled={busy}>
                Zwei-Faktor ausschalten
              </Button>
              <Button type="button" variant="ghost" onClick={() => setDisabling(false)}>
                Abbrechen
              </Button>
            </div>
          </div>
        )}
      </div>
    );
  }

  // 4) off: ask for the password to start
  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-700 dark:text-gray-300">
        Mit der Zwei-Faktor-Anmeldung reicht das Passwort allein nicht mehr zum Einloggen. Zusätzlich wird
        ein Code aus einer App auf deinem Handy verlangt.
      </p>
      <input
        type="password"
        className={inputClass}
        placeholder="Zur Bestätigung: aktuelles Passwort"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        autoComplete="current-password"
      />
      {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
      <Button type="button" onClick={startSetup} disabled={busy || !password}>
        Zwei-Faktor einrichten
      </Button>
    </div>
  );
}
