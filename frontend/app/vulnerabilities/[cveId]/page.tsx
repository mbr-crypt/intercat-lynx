"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { authFetch } from "@/lib/authed-fetch";
import type { VulnerabilityDetail } from "@/lib/api";
import { VulnerabilityDetailView, type BsiHit } from "@/components/VulnerabilityDetail";

type State =
  | { kind: "loading" }
  | { kind: "missing" }
  | { kind: "error" }
  | { kind: "ok"; vuln: VulnerabilityDetail; bsiHits: BsiHit[] };

/**
 * The data is only open to signed-in users and the access token lives in the
 * browser, so the page loads it there (a server-side render could not send it).
 */
export default function VulnerabilityDetailPage() {
  const { cveId } = useParams<{ cveId: string }>();
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    const id = encodeURIComponent(cveId);
    setState({ kind: "loading" });
    (async () => {
      try {
        const [vulnRes, bsiRes] = await Promise.all([
          authFetch(`/api/v1/vulnerabilities/${id}`),
          // a missing BSI answer never breaks the page
          authFetch(`/api/v1/bsi/cve/${id}`).catch(() => null),
        ]);
        if (cancelled) return;
        if (vulnRes.status === 404) return setState({ kind: "missing" });
        if (!vulnRes.ok) return setState({ kind: "error" });
        const vuln = (await vulnRes.json()) as VulnerabilityDetail;
        const bsiHits = bsiRes && bsiRes.ok ? ((await bsiRes.json()) as BsiHit[]) : [];
        if (!cancelled) setState({ kind: "ok", vuln, bsiHits });
      } catch {
        if (!cancelled) setState({ kind: "error" });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [cveId]);

  if (state.kind === "ok") return <VulnerabilityDetailView vuln={state.vuln} bsiHits={state.bsiHits} />;

  const text =
    state.kind === "loading"
      ? "Wird geladen ..."
      : state.kind === "missing"
        ? `${cveId} ist in dieser Installation nicht vorhanden.`
        : "Die Schwachstelle konnte nicht geladen werden.";
  return (
    <div className="space-y-6">
      <Link href="/">
        <Button variant="outline" size="sm">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Dashboard
        </Button>
      </Link>
      <p className="text-sm text-gray-600 dark:text-gray-400" role="status">
        {text}
      </p>
    </div>
  );
}
