'use client';

import { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';

/**
 * On a fresh installation every page leads to the setup assistant.
 * One small public request per page load; failures are ignored so a
 * temporarily unreachable backend never locks users out of the site.
 */
export function SetupGuard() {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (pathname.startsWith('/setup')) return;
    let cancelled = false;
    fetch('/api/v1/setup/status', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!cancelled && data?.setup_required) router.replace('/setup');
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [pathname, router]);

  return null;
}
