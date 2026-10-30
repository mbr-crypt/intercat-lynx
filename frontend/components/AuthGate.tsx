"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { signInUrl } from "@/lib/authed-fetch";

/** Pages that work without signing in: the sign-in itself, the setup assistant, the privacy policy. */
export function isPublicPath(pathname: string): boolean {
  return (
    pathname === "/auth" ||
    pathname.startsWith("/auth/") ||
    pathname === "/setup" ||
    pathname.startsWith("/setup/") ||
    pathname === "/privacy"
  );
}

/**
 * The whole site is for signed-in users only. Until the session is checked
 * nothing is shown, so no page ever asks the API for data without a token;
 * without a session the visitor is sent to the sign-in page and returns to the
 * page they wanted afterwards.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const open = isPublicPath(pathname);

  useEffect(() => {
    if (!open && !isLoading && !user) router.replace(signInUrl());
  }, [open, isLoading, user, router]);

  if (open) return <>{children}</>;
  if (isLoading || !user) {
    return (
      <div className="py-24 text-center text-sm text-gray-500 dark:text-gray-400" role="status">
        Einen Moment, die Anmeldung wird geprüft ...
      </div>
    );
  }
  return <>{children}</>;
}
