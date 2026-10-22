'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, KeyRound } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const inputClass =
  'w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary';

export default function AuthPage() {
  const { login, loginWithCode } = useAuth();
  const router = useRouter();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await login(username, password);
      if (result.mfaRequired) {
        setMfaToken(result.mfaToken ?? null);
        setPassword('');
      } else {
        router.push('/');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const submitCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError('');
    setLoading(true);
    try {
      await loginWithCode(mfaToken, code);
      router.push('/');
    } catch (err: any) {
      setError(err.message);
      setCode('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-10rem)] flex items-center justify-center">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="bg-primary p-3 rounded-2xl">
              <Shield className="h-10 w-10 text-primary-foreground" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">InterCat Lynx</h1>
        </div>

        <Card>
          {!mfaToken ? (
            <>
              <CardHeader>
                <CardTitle className="text-lg">Anmelden</CardTitle>
                <CardDescription>Mit Benutzername und Passwort</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={submitPassword} className="space-y-4">
                  <div>
                    <label htmlFor="username" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
                      Benutzername
                    </label>
                    <input
                      id="username"
                      className={inputClass}
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor="password" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
                      Passwort
                    </label>
                    <input
                      id="password"
                      type="password"
                      className={inputClass}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      required
                    />
                  </div>
                  {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? 'Prüfe…' : 'Weiter'}
                  </Button>
                </form>
              </CardContent>
            </>
          ) : (
            <>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-lg">
                  <KeyRound className="h-5 w-5" />
                  <span>Zweiter Faktor</span>
                </CardTitle>
                <CardDescription>
                  Sechsstelliger Code aus der Authenticator-App. Ohne Handy: einen Wiederherstellungscode
                  eingeben (jeder gilt nur einmal).
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={submitCode} className="space-y-4">
                  <input
                    className={inputClass + ' text-center tracking-widest text-lg'}
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    inputMode="text"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    autoFocus
                    required
                  />
                  {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? 'Prüfe…' : 'Anmelden'}
                  </Button>
                  <button
                    type="button"
                    className="w-full text-sm text-gray-500 hover:underline"
                    onClick={() => {
                      setMfaToken(null);
                      setCode('');
                      setError('');
                    }}
                  >
                    Zurück
                  </button>
                </form>
              </CardContent>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
