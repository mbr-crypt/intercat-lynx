import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navigation } from "@/components/navigation";
import { AuthProvider } from "@/lib/auth-context";
import { ThemeProvider } from "@/lib/theme-context";
import { AnalyticsProvider } from "@/components/AnalyticsProvider";
import { SetupGuard } from "@/components/SetupGuard";
import {
  PRODUCT_NAME,
  SOURCE_URL,
  UPSTREAM_NAME,
  UPSTREAM_URL,
  OPERATOR_EMAIL,
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
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900 overflow-x-hidden transition-colors">
              <Navigation />
              {/* Padding top for fixed nav */}
              <main className="container mx-auto px-4 py-8 pt-20 max-w-full overflow-x-hidden">
                {children}
              </main>
              <footer className="border-t border-gray-200 dark:border-gray-700 mt-12 py-6 text-center text-sm text-gray-600 dark:text-gray-400">
                <p>
                  {PRODUCT_NAME} - a fork of{" "}
                  <a
                    href={UPSTREAM_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:text-primary/80 hover:underline"
                  >
                    {UPSTREAM_NAME}
                  </a>
                </p>
                <p className="mt-1">
                  Data sources: CISA KEV, NVD
                </p>
                <p className="mt-2">
                  <a
                    href={SOURCE_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:text-primary/80 hover:underline"
                  >
                    Source code (AGPL-3.0)
                  </a>
                  {OPERATOR_EMAIL && (
                    <>
                      {" · "}
                      <a
                        href={`mailto:${OPERATOR_EMAIL}`}
                        className="text-primary hover:text-primary/80 hover:underline"
                      >
                        Contact
                      </a>
                    </>
                  )}
                  {" · "}
                  <a
                    href="/privacy"
                    className="text-primary hover:text-primary/80 hover:underline"
                  >
                    Privacy Policy
                  </a>
                  {" · "}
                  <a
                    href="/api/v1/feeds/rss"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:text-primary/80 hover:underline"
                  >
                    RSS Feed
                  </a>
                </p>
              </footer>
            </div>
            </AnalyticsProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
