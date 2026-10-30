"use client";

import { useAuth } from "@/lib/auth-context";

/** The RSS feeds need a login (a reader that cannot sign in cannot use them), so the link is only shown to signed-in users. */
export function FooterFeedLink() {
  const { user } = useAuth();
  if (!user) return null;
  return (
    <a href="/api/v1/feeds/rss" target="_blank" rel="noopener noreferrer" className="text-link hover:underline">
      RSS Feed
    </a>
  );
}
