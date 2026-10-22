"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Ban,
  CheckCircle2,
  Copy,
  KeyRound,
  LogOut,
  Pencil,
  Plus,
  ShieldOff,
  Trash2,
  Unlock,
  Search,
} from "lucide-react";
import {
  adminFetch,
  resetTwoFactor,
  formatDate,
  ROLE_HELP,
  ROLE_LABEL,
  type AdminUser,
  type Paged,
  type Role,
  type UserWithPassword,
} from "@/lib/admin-api";
import {
  Modal,
  dangerButton,
  inputClass,
  primaryButton,
  secondaryButton,
  selectClass,
} from "./Modal";

type ConfirmAction =
  | "deactivate"
  | "activate"
  | "delete"
  | "reset-2fa"
  | "revoke"
  | "reset-password";

type Dialog =
  | null
  | { type: "create" }
  | { type: "edit"; user: AdminUser }
  | { type: "confirm"; user: AdminUser; action: ConfirmAction }
  | { type: "secret"; username: string; password: string; created: boolean };

const CONFIRM_TEXT: Record<ConfirmAction, { title: string; text: string; button: string; danger?: boolean }> = {
  deactivate: {
    title: "Benutzer deaktivieren?",
    text: "Der Benutzer kann sich nicht mehr anmelden, laufende Sitzungen enden sofort. Die Daten bleiben erhalten.",
    button: "Deaktivieren",
  },
  activate: {
    title: "Benutzer aktivieren?",
    text: "Der Benutzer kann sich wieder anmelden.",
    button: "Aktivieren",
  },
  delete: {
    title: "Benutzer endgültig löschen?",
    text: "Das Konto und alle zugehörigen Daten (Lesezeichen, Stimmen, Kommentare, Benachrichtigungen, Tech-Stacks) werden gelöscht. Das lässt sich nicht rückgängig machen. Zum Sperren reicht „Deaktivieren“.",
    button: "Endgültig löschen",
    danger: true,
  },
  "reset-2fa": {
    title: "Zwei-Faktor-Anmeldung zurücksetzen?",
    text: "Die 2FA wird ausgeschaltet, alle Wiederherstellungscodes werden ungültig und laufende Sitzungen enden. Der Benutzer sollte sie danach neu einrichten. Prüfen Sie vorher, dass wirklich der Kontoinhaber fragt.",
    button: "2FA zurücksetzen",
    danger: true,
  },
  revoke: {
    title: "Überall abmelden?",
    text: "Alle laufenden Sitzungen dieses Benutzers enden. Er kann sich sofort wieder anmelden.",
    button: "Abmelden",
  },
  "reset-password": {
    title: "Passwort zurücksetzen?",
    text: "Es wird ein neues, vorläufiges Passwort erzeugt. Das alte Passwort und alle laufenden Sitzungen werden ungültig, der Benutzer muss beim nächsten Login ein eigenes Passwort wählen.",
    button: "Neues Passwort erzeugen",
  },
};

export function UsersPanel({ token, currentUserId }: { token: string; currentUserId: number }) {
  const [data, setData] = useState<Paged<AdminUser> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [role, setRole] = useState("");
  const [status, setStatus] = useState("");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [notice, setNotice] = useState("");
  const [registration, setRegistration] = useState<boolean | null>(null);

  // Wait a moment after typing before asking the server
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(query.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [query]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ page: String(page), page_size: "25" });
      if (search) params.set("q", search);
      if (role) params.set("role", role);
      if (status) params.set("status", status);
      setData(await adminFetch<Paged<AdminUser>>(token, `/users?${params}`));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [token, page, search, role, status]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    adminFetch<{ registration_enabled: boolean }>(token, "/users/settings/registration")
      .then((r) => setRegistration(r.registration_enabled))
      .catch(() => setRegistration(null));
  }, [token]);

  const flash = (text: string) => {
    setNotice(text);
    setTimeout(() => setNotice(""), 4000);
  };

  const toggleRegistration = async () => {
    if (registration === null) return;
    try {
      const r = await adminFetch<{ registration_enabled: boolean }>(
        token,
        "/users/settings/registration",
        { method: "PUT", body: { registration_enabled: !registration } }
      );
      setRegistration(r.registration_enabled);
      flash(r.registration_enabled ? "Registrierung ist offen." : "Registrierung ist geschlossen.");
    } catch (e: any) {
      setError(e.message);
    }
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-4">
      {/* Registration policy */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-white p-4 dark:bg-gray-800">
        <div>
          <p className="font-medium text-gray-900 dark:text-white">Offene Registrierung</p>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Wenn aus, können sich Besucher nicht selbst ein Konto anlegen. Konten legen dann nur
            Administratoren an. Für private Installationen empfohlen.
          </p>
        </div>
        <button
          onClick={toggleRegistration}
          disabled={registration === null}
          role="switch"
          aria-checked={!!registration}
          aria-label="Offene Registrierung"
          className={`relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-50 ${
            registration ? "bg-blue-600" : "bg-gray-300 dark:bg-gray-600"
          }`}
        >
          <span
            className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${
              registration ? "left-[22px]" : "left-0.5"
            }`}
          />
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[14rem] flex-1">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Suchen: Benutzername, E-Mail, Name"
            aria-label="Benutzer suchen"
            className={`${inputClass} pl-9`}
          />
        </div>
        <select
          value={role}
          onChange={(e) => {
            setRole(e.target.value);
            setPage(1);
          }}
          aria-label="Nach Rolle filtern"
          className={selectClass}
        >
          <option value="">Alle Rollen</option>
          {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
            <option key={r} value={r}>
              {ROLE_LABEL[r]}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          aria-label="Nach Status filtern"
          className={selectClass}
        >
          <option value="">Alle Status</option>
          <option value="active">Aktiv</option>
          <option value="inactive">Deaktiviert</option>
          <option value="locked">Gesperrt</option>
        </select>
        <button className={primaryButton} onClick={() => setDialog({ type: "create" })}>
          <Plus className="h-4 w-4" /> Benutzer anlegen
        </button>
      </div>

      {notice && (
        <p role="status" className="rounded-lg bg-green-50 p-3 text-sm text-green-800 dark:bg-green-900/20 dark:text-green-200">
          {notice}
        </p>
      )}
      {error && (
        <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
          {error}
        </p>
      )}

      {/* Table */}
      <div className="overflow-x-auto rounded-2xl bg-white dark:bg-gray-800">
        <table className="w-full min-w-[56rem] text-left text-sm">
          <thead className="border-b border-gray-200 text-xs uppercase tracking-wide text-gray-500 dark:border-gray-700 dark:text-gray-400">
            <tr>
              <th className="px-4 py-3 font-semibold">Benutzer</th>
              <th className="px-4 py-3 font-semibold">Rolle</th>
              <th className="px-4 py-3 font-semibold">Status</th>
              <th className="px-4 py-3 font-semibold">Letzter Login</th>
              <th className="px-4 py-3 text-right font-semibold">Aktionen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {data?.items.map((u) => (
              <UserRow
                key={u.id}
                user={u}
                isSelf={u.id === currentUserId}
                onEdit={() => setDialog({ type: "edit", user: u })}
                onAction={(action) => setDialog({ type: "confirm", user: u, action })}
                onUnlock={async () => {
                  try {
                    await adminFetch(token, `/users/${u.id}/unlock`, { method: "POST" });
                    flash(`Sperre für ${u.username} aufgehoben.`);
                    load();
                  } catch (e: any) {
                    setError(e.message);
                  }
                }}
              />
            ))}
            {data && data.items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  Keine Benutzer gefunden.
                </td>
              </tr>
            )}
            {!data && loading && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  Lädt ...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {data && (
        <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
          <span>{data.total} Benutzer</span>
          <div className="flex items-center gap-2">
            <button className={secondaryButton} disabled={page <= 1} onClick={() => setPage(page - 1)}>
              Zurück
            </button>
            <span>
              Seite {page} von {totalPages}
            </span>
            <button className={secondaryButton} disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
              Weiter
            </button>
          </div>
        </div>
      )}

      {dialog?.type === "create" && (
        <CreateDialog
          token={token}
          onClose={() => setDialog(null)}
          onCreated={(r) => {
            setDialog(
              r.temporary_password
                ? { type: "secret", username: r.user.username, password: r.temporary_password, created: true }
                : null
            );
            if (!r.temporary_password) flash(`Benutzer ${r.user.username} angelegt.`);
            load();
          }}
        />
      )}
      {dialog?.type === "edit" && (
        <EditDialog
          token={token}
          user={dialog.user}
          isSelf={dialog.user.id === currentUserId}
          onClose={() => setDialog(null)}
          onSaved={() => {
            setDialog(null);
            flash("Änderungen gespeichert.");
            load();
          }}
        />
      )}
      {dialog?.type === "confirm" && (
        <ConfirmDialog
          user={dialog.user}
          action={dialog.action}
          onClose={() => setDialog(null)}
          onConfirm={async () => {
            const { user, action } = dialog;
            if (action === "reset-2fa") await resetTwoFactor(token, user.id);
            else if (action === "delete")
              await adminFetch(token, `/users/${user.id}`, { method: "DELETE" });
            else if (action === "deactivate" || action === "activate")
              await adminFetch(token, `/users/${user.id}`, {
                method: "PATCH",
                body: { is_active: action === "activate" },
              });
            else if (action === "revoke")
              await adminFetch(token, `/users/${user.id}/revoke-sessions`, { method: "POST" });
            else if (action === "reset-password") {
              const r = await adminFetch<UserWithPassword>(token, `/users/${user.id}/reset-password`, {
                method: "POST",
                body: {},
              });
              setDialog({
                type: "secret",
                username: user.username,
                password: r.temporary_password ?? "",
                created: false,
              });
              load();
              return;
            }
            setDialog(null);
            flash("Erledigt.");
            load();
          }}
        />
      )}
      {dialog?.type === "secret" && (
        <SecretDialog
          username={dialog.username}
          password={dialog.password}
          created={dialog.created}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

function Badge({ children, tone }: { children: React.ReactNode; tone: "green" | "red" | "amber" | "blue" | "gray" }) {
  const tones = {
    green: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
    red: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    amber: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
    blue: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300",
    gray: "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300",
  };
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>;
}

function IconButton({
  label,
  onClick,
  disabled,
  danger,
  children,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={label}
      aria-label={label}
      className={`rounded-lg p-1.5 disabled:cursor-not-allowed disabled:opacity-30 ${
        danger
          ? "text-gray-500 hover:bg-red-50 hover:text-red-600 dark:text-gray-400 dark:hover:bg-red-900/20 dark:hover:text-red-400"
          : "text-gray-500 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-700 dark:hover:text-white"
      }`}
    >
      {children}
    </button>
  );
}

function UserRow({
  user,
  isSelf,
  onEdit,
  onAction,
  onUnlock,
}: {
  user: AdminUser;
  isSelf: boolean;
  onEdit: () => void;
  onAction: (a: ConfirmAction) => void;
  onUnlock: () => void;
}) {
  return (
    <tr className={user.is_active ? "" : "opacity-60"}>
      <td className="px-4 py-3">
        <div className="font-medium text-gray-900 dark:text-white">
          {user.username}
          {isSelf && <span className="ml-2 text-xs font-normal text-gray-500">(Sie)</span>}
        </div>
        <div className="text-gray-600 dark:text-gray-400">
          {user.full_name ? `${user.full_name} · ` : ""}
          {user.email}
        </div>
      </td>
      <td className="px-4 py-3">
        <Badge tone={user.role === "admin" ? "red" : user.role === "analyst" ? "blue" : "gray"}>
          {ROLE_LABEL[user.role]}
        </Badge>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {user.is_active ? <Badge tone="green">Aktiv</Badge> : <Badge tone="gray">Deaktiviert</Badge>}
          {user.is_locked && <Badge tone="red">Gesperrt</Badge>}
          {user.totp_enabled && <Badge tone="blue">2FA</Badge>}
          {user.must_change_password && <Badge tone="amber">Passwortwechsel offen</Badge>}
        </div>
      </td>
      <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{formatDate(user.last_login_at)}</td>
      <td className="px-4 py-3">
        <div className="flex justify-end gap-0.5">
          <IconButton label="Bearbeiten" onClick={onEdit}>
            <Pencil className="h-4 w-4" />
          </IconButton>
          {user.is_locked && (
            <IconButton label="Sperre aufheben" onClick={onUnlock}>
              <Unlock className="h-4 w-4" />
            </IconButton>
          )}
          <IconButton label="Passwort zurücksetzen" onClick={() => onAction("reset-password")} disabled={isSelf}>
            <KeyRound className="h-4 w-4" />
          </IconButton>
          <IconButton label="2FA zurücksetzen" onClick={() => onAction("reset-2fa")} disabled={!user.totp_enabled}>
            <ShieldOff className="h-4 w-4" />
          </IconButton>
          <IconButton label="Überall abmelden" onClick={() => onAction("revoke")}>
            <LogOut className="h-4 w-4" />
          </IconButton>
          {user.is_active ? (
            <IconButton label="Deaktivieren" onClick={() => onAction("deactivate")} disabled={isSelf}>
              <Ban className="h-4 w-4" />
            </IconButton>
          ) : (
            <IconButton label="Aktivieren" onClick={() => onAction("activate")}>
              <CheckCircle2 className="h-4 w-4" />
            </IconButton>
          )}
          <IconButton label="Löschen" onClick={() => onAction("delete")} disabled={isSelf} danger>
            <Trash2 className="h-4 w-4" />
          </IconButton>
        </div>
      </td>
    </tr>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">{hint}</span>}
    </label>
  );
}

function RoleSelect({ value, onChange, disabled }: { value: Role; onChange: (r: Role) => void; disabled?: boolean }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as Role)}
      disabled={disabled}
      className={inputClass}
    >
      {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
        <option key={r} value={r}>
          {ROLE_LABEL[r]} - {ROLE_HELP[r]}
        </option>
      ))}
    </select>
  );
}

function CreateDialog({
  token,
  onClose,
  onCreated,
}: {
  token: string;
  onClose: () => void;
  onCreated: (r: UserWithPassword) => void;
}) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body: Record<string, unknown> = { username, email, role };
      if (fullName.trim()) body.full_name = fullName.trim();
      if (password) body.password = password;
      onCreated(await adminFetch<UserWithPassword>(token, "/users", { method: "POST", body }));
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Modal title="Benutzer anlegen" onClose={onClose} wide>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Benutzername" hint="Buchstaben, Ziffern, _ und -">
            <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} maxLength={100} pattern="[a-zA-Z0-9_\-]+" autoFocus />
          </Field>
          <Field label="E-Mail">
            <input className={inputClass} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </Field>
        </div>
        <Field label="Name (optional)">
          <input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} maxLength={255} />
        </Field>
        <Field label="Rolle">
          <RoleSelect value={role} onChange={setRole} />
        </Field>
        <Field
          label="Passwort (optional)"
          hint="Leer lassen: Es wird ein vorläufiges Passwort erzeugt. In beiden Fällen muss der Benutzer beim ersten Login ein eigenes wählen."
        >
          <input className={inputClass} type="text" autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} maxLength={100} />
        </Field>
        {error && (
          <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className={secondaryButton} onClick={onClose}>
            Abbrechen
          </button>
          <button type="submit" className={primaryButton} disabled={busy}>
            {busy ? "Legt an ..." : "Anlegen"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditDialog({
  token,
  user,
  isSelf,
  onClose,
  onSaved,
}: {
  token: string;
  user: AdminUser;
  isSelf: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [email, setEmail] = useState(user.email);
  const [fullName, setFullName] = useState(user.full_name ?? "");
  const [role, setRole] = useState<Role>(user.role);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const body: Record<string, unknown> = {};
    if (email !== user.email) body.email = email;
    if (fullName !== (user.full_name ?? "")) body.full_name = fullName;
    if (role !== user.role) body.role = role;
    try {
      if (Object.keys(body).length > 0) {
        await adminFetch(token, `/users/${user.id}`, { method: "PATCH", body });
      }
      onSaved();
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Modal title={`${user.username} bearbeiten`} onClose={onClose} wide>
      <form onSubmit={submit} className="space-y-4">
        <Field label="E-Mail">
          <input className={inputClass} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label="Name">
          <input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} maxLength={255} />
        </Field>
        <Field
          label="Rolle"
          hint={
            isSelf
              ? "Die eigene Rolle lässt sich hier nicht ändern. Das schützt davor, sich auszusperren."
              : "Eine Rollenänderung beendet die laufenden Sitzungen des Benutzers."
          }
        >
          <RoleSelect value={role} onChange={setRole} disabled={isSelf} />
        </Field>
        {error && (
          <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className={secondaryButton} onClick={onClose}>
            Abbrechen
          </button>
          <button type="submit" className={primaryButton} disabled={busy}>
            {busy ? "Speichert ..." : "Speichern"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ConfirmDialog({
  user,
  action,
  onClose,
  onConfirm,
}: {
  user: AdminUser;
  action: ConfirmAction;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [typed, setTyped] = useState("");
  const text = CONFIRM_TEXT[action];
  const needsTyping = action === "delete";

  return (
    <Modal title={text.title} onClose={onClose}>
      <p className="mb-1 text-sm font-medium text-gray-900 dark:text-white">{user.username}</p>
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">{text.text}</p>
      {needsTyping && (
        <Field label={`Zur Bestätigung den Benutzernamen eintippen (${user.username})`}>
          <input className={inputClass} value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
        </Field>
      )}
      {error && (
        <p role="alert" className="mt-3 rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-900/20 dark:text-red-200">
          {error}
        </p>
      )}
      <div className="mt-5 flex justify-end gap-2">
        <button className={secondaryButton} onClick={onClose}>
          Abbrechen
        </button>
        <button
          className={text.danger ? dangerButton : primaryButton}
          disabled={busy || (needsTyping && typed !== user.username)}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await onConfirm();
            } catch (e: any) {
              setError(e.message);
              setBusy(false);
            }
          }}
        >
          {busy ? "Bitte warten ..." : text.button}
        </button>
      </div>
    </Modal>
  );
}

function SecretDialog({
  username,
  password,
  created,
  onClose,
}: {
  username: string;
  password: string;
  created: boolean;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
    } catch {
      /* clipboard not available: the password is visible and can be selected */
    }
  };
  return (
    <Modal title={created ? "Benutzer angelegt" : "Neues Passwort"} onClose={onClose}>
      <p className="mb-3 text-sm text-gray-600 dark:text-gray-400">
        Vorläufiges Passwort für <strong className="text-gray-900 dark:text-white">{username}</strong>.
        Es wird <strong>nur jetzt</strong> angezeigt und ist nirgends gespeichert. Geben Sie es auf
        sicherem Weg weiter. Beim ersten Login muss der Benutzer ein eigenes Passwort wählen.
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 select-all break-all rounded-lg bg-gray-100 px-3 py-2 font-mono text-base text-gray-900 dark:bg-gray-900 dark:text-white">
          {password}
        </code>
        <button className={secondaryButton} onClick={copy} aria-label="Passwort kopieren">
          <Copy className="h-4 w-4" /> {copied ? "Kopiert" : "Kopieren"}
        </button>
      </div>
      <div className="mt-5 flex justify-end">
        <button className={primaryButton} onClick={onClose}>
          Fertig
        </button>
      </div>
    </Modal>
  );
}
