"use client";

/**
 * Activity icon in the header (administrators only): shows what the system does in
 * the background right now, currently the data import. It is only visible while
 * something runs or something went wrong that has not been looked at yet.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity as ActivityIcon, AlertTriangle, CheckCircle2, X } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { useActivity } from "@/lib/use-activity";
import { ImportProgress } from "./ImportProgress";

const SEEN_KEY = "lynx_activity_seen";
// A finished import stays visible for this long
const DONE_VISIBLE_MS = 15 * 60 * 1000;

function readSeen(): string | null {
  try {
    return localStorage.getItem(SEEN_KEY);
  } catch {
    return null;
  }
}

function writeSeen(value: string) {
  try {
    localStorage.setItem(SEEN_KEY, value);
  } catch {
    /* private window, blocked storage: the icon then simply stays */
  }
}

export function ActivityIndicator() {
  const { token, user, isAuthenticated } = useAuth();
  const isAdmin = isAuthenticated && user?.role === "admin";
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState<string | null>(null);
  const { importActivity, running, connectionLost, receivedAt } = useActivity(token, !!isAdmin, open);

  useEffect(() => setSeen(readSeen()), []);

  if (!isAdmin || !importActivity) return null;

  const runId = importActivity.started_at ?? "";
  const failed = importActivity.state === "error" || importActivity.state === "interrupted";
  const finishedAt = importActivity.finished_at ? new Date(importActivity.finished_at).getTime() : 0;
  const recentlyDone = importActivity.state === "done" && Date.now() - finishedAt < DONE_VISIBLE_MS;
  const dismissed = seen === `${runId}:${importActivity.state}`;
  const visible = running || open || ((failed || recentlyDone) && !dismissed);
  if (!visible) return null;

  const close = () => {
    setOpen(false);
    if (!running) {
      const value = `${runId}:${importActivity.state}`;
      writeSeen(value);
      setSeen(value);
    }
  };

  const label = running
    ? "Hintergrundaktivität: Import läuft"
    : failed
      ? "Hintergrundaktivität: Import fehlgeschlagen"
      : "Hintergrundaktivität: Import abgeschlossen";

  return (
    <div className="relative">
      <button
        onClick={() => (open ? close() : setOpen(true))}
        className="relative rounded-full p-2 text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
        aria-label={label}
        aria-expanded={open}
      >
        <ActivityIcon className={`h-6 w-6 ${running ? "text-primary" : ""}`} />
        {running && (
          <span className="absolute right-1 top-1 flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60 motion-reduce:animate-none" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-primary" />
          </span>
        )}
        {failed && <span className="absolute right-1 top-1 h-2.5 w-2.5 rounded-full bg-red-600" />}
        {!running && !failed && <span className="absolute right-1 top-1 h-2.5 w-2.5 rounded-full bg-green-600" />}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={close} />
          <div
            role="dialog"
            aria-label="Hintergrundaktivität"
            className="absolute right-0 z-50 mt-2 w-[22rem] max-w-[calc(100vw-2rem)] rounded-lg border border-gray-200 bg-white p-4 shadow-xl dark:border-gray-700 dark:bg-gray-800"
          >
            <div className="mb-3 flex items-start justify-between gap-2">
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white">
                  {failed ? (
                    <AlertTriangle className="h-4 w-4 text-red-600" aria-hidden />
                  ) : importActivity.state === "done" ? (
                    <CheckCircle2 className="h-4 w-4 text-green-600" aria-hidden />
                  ) : (
                    <ActivityIcon className="h-4 w-4 text-primary" aria-hidden />
                  )}
                  {importActivity.title}
                </h2>
              </div>
              <button onClick={close} aria-label="Schließen" className="rounded p-1 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700">
                <X className="h-4 w-4" />
              </button>
            </div>
            <ImportProgress status={importActivity} receivedAt={receivedAt} connectionLost={connectionLost} />
            <div className="mt-3 border-t border-gray-200 pt-3 text-sm dark:border-gray-700">
              <Link href="/admin?tab=data" onClick={close} className="text-blue-600 hover:underline dark:text-blue-400">
                Zu Administration → Daten
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
