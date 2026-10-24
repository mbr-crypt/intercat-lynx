"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { UsersPanel } from "@/components/admin/UsersPanel";
import { AuditPanel } from "@/components/admin/AuditPanel";
import { ImportPanel } from "@/components/admin/ImportPanel";

type Tab = "users" | "audit" | "data";

export default function AdminPage() {
  const { user, token, isLoading } = useAuth();
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("users");

  useEffect(() => {
    if (!isLoading && !user) router.push("/auth");
  }, [user, isLoading, router]);

  // The activity icon in the header links to /admin?tab=data
  useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("tab");
    if (wanted === "data" || wanted === "audit" || wanted === "users") setTab(wanted);
  }, []);

  if (isLoading || !user || !token) return null;

  if (user.role !== "admin") {
    return (
      <div className="mx-auto max-w-2xl rounded-2xl bg-white p-8 text-center dark:bg-gray-800">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Kein Zugriff</h1>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Die Administration ist Administratoren vorbehalten.
        </p>
      </div>
    );
  }

  const tabClass = (t: Tab) =>
    `rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
      tab === t
        ? "bg-blue-600/10 text-blue-600 dark:text-blue-400"
        : "text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
    }`;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <p className="mb-2 flex items-center gap-3 text-xs font-semibold uppercase tracking-[0.15em] text-blue-600 dark:text-blue-400">
          <span className="h-px w-8 bg-gradient-to-r from-blue-600 to-blue-400" />
          InterCat Lynx
        </p>
        <h1 className="text-3xl font-semibold text-gray-900 dark:text-white">Administration</h1>
      </div>

      <div role="tablist" className="flex gap-2">
        <button role="tab" aria-selected={tab === "users"} className={tabClass("users")} onClick={() => setTab("users")}>
          Benutzer
        </button>
        <button role="tab" aria-selected={tab === "audit"} className={tabClass("audit")} onClick={() => setTab("audit")}>
          Protokoll
        </button>
        <button role="tab" aria-selected={tab === "data"} className={tabClass("data")} onClick={() => setTab("data")}>
          Daten
        </button>
      </div>

      {tab === "users" ? (
        <UsersPanel token={token} currentUserId={user.id} />
      ) : tab === "audit" ? (
        <AuditPanel token={token} />
      ) : (
        <ImportPanel token={token} />
      )}
    </div>
  );
}
