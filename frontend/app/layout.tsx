import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navigation } from "@/components/navigation";
import { AuthProvider } from "@/lib/auth-context";
import { ThemeProvider } from "@/lib/theme-context";
import { AnalyticsProvider } from "@/components/AnalyticsProvider";
import { SetupGuard } from "@/components/SetupGuard";
import { PasswordChangeGuard } from "@/components/PasswordChangeGuard";
import { BrandProvider } from "@/lib/brand-context";
import type { Brand } from "@/lib/brand";
import { getBrand } from "@/lib/brand-server";
import { accentCss } from "@/lib/brand-colors";
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

export async function generateMetadata(): Promise<Metadata> {
  const brand = await getBrand();
  return {
    title: `${brand.name} - Vulnerability Intelligence`,
    description: `${brand.name}: CVE tracking and vulnerability intelligence. Open source (AGPL-3.0), based on ${PRODUCT_NAME}, a fork of ${UPSTREAM_NAME}.`,
    alternates: {
      types: {
        "application/rss+xml": [
          { url: "/api/v1/feeds/rss", title: `${brand.name} - Recent Vulnerabilities` },
          { url: "/api/v1/feeds/exploited", title: `${brand.name} - Actively Exploited Vulnerabilities` },
          { url: "/api/v1/feeds/critical", title: `${brand.name} - Critical Vulnerabilities` },
        ],
      },
    },
  };
}

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const brand = await getBrand();
  const accent = accentCss(brand.accent);
  const hasLogo = Boolean(brand.logo_light || brand.logo_dark);
  const renamed = brand.name !== PRODUCT_NAME;
  return (
    <html lang="en" suppressHydrationWarning>
      {/* Accent colour of the instance. The text is built from a checked #rrggbb value only. */}
      <head>{accent ? <style dangerouslySetInnerHTML={{ __html: accent }} /> : null}</head>
      <body className={inter.className}>
        <BrandProvider brand={brand}>
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
                    <FooterBrand brand={brand} hasLogo={hasLogo} />
                    <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                      {renamed ? (
                        <>
                          {brand.name} is based on {PRODUCT_NAME}, a fork of{" "}
                        </>
                      ) : (
                        <>{PRODUCT_NAME} - a fork of{" "}</>
                      )}
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
                    {brand.footer_text && (
                      <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">{brand.footer_text}</p>
                    )}
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
        </BrandProvider>
      </body>
    </html>
  );
}

/**
 * Logo or name at the top of the footer. Default instance: the Intercat wordmark
 * (Styleguide: white on dark, black on light). With an own logo: that logo; with only
 * an own name: the name as text.
 */
function FooterBrand({ brand, hasLogo }: { brand: Brand; hasLogo: boolean }) {
  const wrap = (href: string | null, label: string, children: React.ReactNode) =>
    href ? (
      <a href={href} target="_blank" rel="noopener noreferrer" aria-label={label}>
        {children}
      </a>
    ) : (
      <div aria-label={label}>{children}</div>
    );

  if (hasLogo) {
    const imgClass = "h-10 w-auto max-w-[16rem] object-contain object-left";
    return wrap(
      brand.url,
      brand.name,
      <>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={brand.logo_dark ?? brand.logo_light!} alt={brand.name} className={`hidden dark:block ${imgClass}`} />
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={brand.logo_light ?? brand.logo_dark!} alt={brand.name} className={`dark:hidden ${imgClass}`} />
      </>
    );
  }

  if (brand.custom && brand.name !== PRODUCT_NAME) {
    return wrap(
      brand.url,
      brand.name,
      <span className="text-xl font-semibold tracking-tight text-gray-900 dark:text-white">{brand.name}</span>
    );
  }

  return wrap(
    brand.url ?? BRAND_SITE_URL,
    "Intercat",
    <>
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
    </>
  );
}
