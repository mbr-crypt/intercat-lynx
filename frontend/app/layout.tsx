import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navigation } from "@/components/navigation";
import { AuthProvider } from "@/lib/auth-context";
import { ThemeProvider } from "@/lib/theme-context";
import { AnalyticsProvider } from "@/components/AnalyticsProvider";
import { SetupGuard } from "@/components/SetupGuard";
import { PasswordChangeGuard } from "@/components/PasswordChangeGuard";
import {
  PRODUCT_NAME,
  SOURCE_URL,
  UPSTREAM_NAME,
  UPSTREAM_URL,
  OPERATOR_EMAIL,
  BRAND_OWNER,
  BRAND_SITE_URL,
} from "@/lib/branding";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: `${PRODUCT_NAME} - Vulnerability Intelligence`,
  description: `${PRODUCT_NAME}: CVE tracking and vulnerability intelligence. Open source (AGPL-3.0), based on ${UPSTREAM_NAME}.`,
  alternates: {
    types: {
      "application/rss+xml": [
        { url: "/api/v1/feeds/rss", title: `${PRODUCT_NAME} - Recent Vulnerabilities` },
        { url: "/api/v1/feeds/exploited", title: `${PRODUCT_NAME} - Actively Exploited Vulnerabilities` },
        { url: "/api/v1/feeds/critical", title: `${PRODUCT_NAME} - Critical Vulnerabilities` },
      ],
    },
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <ThemeProvider>
          <AuthProvider>
            <AnalyticsProvider>
            <SetupGuard />
            <PasswordChangeGuard />
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900 overflow-x-hidden transition-colors">
              <Navigation />
              {/* Padding top for fixed nav */}
              <main className="container mx-auto px-4 py-8 pt-20 max-w-full overflow-x-hidden">
                {children}
              </main>
              <footer className="border-t border-gray-200 dark:border-gray-700 mt-12">
                <div className="container mx-auto max-w-6xl px-4 py-10 flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
                  <div className="max-w-sm">
                    <a href={BRAND_SITE_URL} target="_blank" rel="noopener noreferrer" aria-label="Intercat">
                      {/* Wortmarke: white on dark, black on light (Styleguide: only these two colours) */}
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src="/brand/intercat-wortmarke-weiss.png"
                        alt="Intercat - Secure. Fast. Reliable."
                        width={1708}
                        height={323}
                        className="hidden dark:block h-10 w-auto"
                      />
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src="/brand/intercat-wortmarke-schwarz.png"
                        alt="Intercat - Secure. Fast. Reliable."
                        width={1708}
                        height={323}
                        className="dark:hidden h-10 w-auto"
                      />
                    </a>
                    <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                      {PRODUCT_NAME} - a fork of{" "}
                      <a
                        href={UPSTREAM_URL}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-link hover:underline"
                      >
                        {UPSTREAM_NAME}
                      </a>
                      . Data sources: CISA KEV, NVD.
                    </p>
                  </div>
                  <nav
                    aria-label="Footer"
                    className="flex flex-wrap gap-x-6 gap-y-2 text-sm md:justify-end"
                  >
                    <a
                      href={SOURCE_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-link hover:underline"
                    >
                      Source code (AGPL-3.0)
                    </a>
                    {OPERATOR_EMAIL && (
                      <a href={`mailto:${OPERATOR_EMAIL}`} className="text-link hover:underline">
                        Contact
                      </a>
                    )}
                    <a href="/privacy" className="text-link hover:underline">
                      Privacy Policy
                    </a>
                    <a
                      href="/api/v1/feeds/rss"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-link hover:underline"
                    >
                      RSS Feed
                    </a>
                  </nav>
                </div>
                <div className="border-t border-gray-200 dark:border-gray-700">
                  <p className="container mx-auto max-w-6xl px-4 py-4 text-xs text-gray-500 dark:text-gray-400">
                    &copy; {BRAND_OWNER}. The names and logos &quot;Intercat&quot; and &quot;{PRODUCT_NAME}&quot; are
                    the property of {BRAND_OWNER} and are not covered by the AGPL-3.0.
                  </p>
                </div>
              </footer>
            </div>
            </AnalyticsProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
