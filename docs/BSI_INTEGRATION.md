> **Status (InterCat Lynx):** Der Backend-Service `bsi_cert_service` wurde upstream im Cleanup (#17) entfernt; `scripts/fetch_bsi_cert.py` und der Endpunkt `bsi-cert/fetch` existieren nicht mehr. Dieses Dokument beschreibt die ursprüngliche Planung. Eine Neuimplementierung steht auf der Roadmap.

# BSI CERT-Bund Integration

## 🇩🇪 Übersicht

OpenThreat integriert Sicherheitswarnungen vom **BSI CERT-Bund** (Bundesamt für Sicherheit in der Informationstechnik).

---

## 📍 Wo sind BSI-Informationen sichtbar?

### 1. **Navigation - Eigene Seite** ⭐ **NEU**

**Zugriff:** Klick auf "🇩🇪 BSI" in der Hauptnavigation

**Was du siehst:**
- Übersicht über BSI CERT-Bund
- Links zum offiziellen Portal
- Informationen über die Integration
- Zukünftig: Liste aller BSI-Advisories

**URL:** `http://localhost:3000/bsi-advisories`

---

### 2. **CVE Detail-Seite - BSI Badge**

**Wann sichtbar:** Wenn ein CVE von BSI CERT-Bund referenziert wird

**Wo:** Im Header neben dem CVE-ID

**Aussehen:**
```
CVE-2024-1234  [CRITICAL]  [🔴 Exploited in Wild]  [🇩🇪 BSI CERT]
```

**Badge-Farbe:** Blau (`bg-blue-100 text-blue-800`)

---

### 3. **CVE Detail-Seite - References Section**

**Wann sichtbar:** Wenn BSI-Referenzen vorhanden sind

**Wo:** In der "References" Sektion ganz unten

**Aussehen:**
```
🔗 https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2308
   [🇩🇪 BSI CERT-Bund]  [advisory]
```

---

### 4. **API Endpoints**

**Status prüfen:**
```bash
curl http://localhost:8001/api/v1/data-sources/bsi-cert/status
```

**Response:**
```json
{
  "source": "bsi_cert",
  "status": "active",
  "vulnerabilities_with_bsi_source": 0,
  "vulnerabilities_with_bsi_references": 0,
  "rss_feed": "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
}
```

**Manuell triggern:**
```bash
curl -X POST http://localhost:8001/api/v1/data-sources/bsi-cert/fetch
```

---

## 🔍 Warum sehe ich noch keine BSI-Daten?

### Problem: RSS-Feed enthält keine CVE-IDs

Der BSI CERT-Bund RSS-Feed sieht so aus:

```xml
<item>
  <title>[hoch] Microsoft Windows: Mehrere Schwachstellen</title>
  <description>Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen...</description>
  <link>https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2308</link>
</item>
```

**Problem:** Die CVE-IDs stehen **nicht** im RSS-Feed!

**Wo sind die CVEs?** Nur auf den Detail-Seiten (Angular-App, dynamisch geladen)

---

## 🛠️ Aktuelle Implementierung

### Was funktioniert:

✅ **RSS-Feed Parsing**
- Fetcht BSI-Advisories
- Extrahiert Titel, Links, Severity
- Speichert Advisory-IDs

✅ **API Endpoints**
- Status-Abfrage
- Manuelles Triggern
- Datenquellen-Liste

✅ **Frontend Integration**
- Eigene BSI-Seite
- BSI-Badge im CVE-Header
- BSI-Badge bei References
- Navigation-Link

✅ **Celery Task**
- Automatisches tägliches Fetching (08:00 UTC)
- Background-Processing

### Was noch fehlt:

❌ **CVE-Extraktion aus Detail-Seiten**
- BSI-Portal ist eine Angular-App
- Daten werden dynamisch geladen
- Benötigt Headless Browser (Playwright/Selenium)

❌ **Direkte BSI-API**
- BSI hat keine öffentliche JSON-API
- Nur RSS-Feed verfügbar
- Detail-Seiten müssen gescraped werden

---

## 🚀 Nächste Schritte

### Option A: Web Scraping (Komplex)

**Implementierung:**
```python
# Mit Playwright/Selenium
async def fetch_advisory_details(advisory_id):
    browser = await playwright.chromium.launch()
    page = await browser.new_page()
    await page.goto(f"https://wid.cert-bund.de/portal/wid/securityadvisory?name={advisory_id}")
    await page.wait_for_selector('.cve-list')
    cves = await page.query_selector_all('.cve-id')
    return [cve.text_content() for cve in cves]
```

**Vorteile:**
- Vollständige Daten
- CVE-Referenzen
- Deutsche Beschreibungen

**Nachteile:**
- Komplex
- Langsam
- Fragil (bei UI-Änderungen)
- Benötigt Headless Browser

---

### Option B: Manuelle Zuordnung (Einfach)

**Implementierung:**
- BSI-Advisories als separate Entität speichern
- Manuelle Verknüpfung mit CVEs
- Anzeige auf eigener Seite

**Vorteile:**
- Einfach
- Stabil
- Schnell

**Nachteile:**
- Keine automatische CVE-Verknüpfung
- Separate Ansicht nötig

---

### Option C: Hybrid-Ansatz (Empfohlen) ⭐

**Implementierung:**
1. RSS-Feed für neue Advisories
2. Separate BSI-Advisory-Seite
3. Manuelle CVE-Verknüpfung wo möglich
4. Später: Scraping für wichtige Advisories

**Vorteile:**
- Sofort nutzbar
- Erweiterbar
- Pragmatisch

**Nachteile:**
- Nicht vollständig automatisch

---

## 📊 Aktuelle Statistiken

```bash
# Prüfen
python scripts/fetch_bsi_cert.py --dry-run --limit 10
```

**Output:**
```
Fetched 10 advisories
Found 0 CVE references in advisories  ← Problem!

1. [hoch] F5 BIG-IP: Mehrere Schwachstellen
   CVEs: None  ← Keine CVEs im RSS-Feed
```

---

## 🎯 Empfehlung

**Kurzfristig:**
1. ✅ BSI-Seite nutzen (bereits implementiert)
2. ✅ Manuelle Links zu BSI-Portal
3. ✅ BSI als Datenquelle dokumentieren

**Mittelfristig:**
4. ⏳ Web Scraping für Top-Advisories
5. ⏳ CVE-Verknüpfung wo möglich

**Langfristig:**
6. 🔮 BSI-API anfragen (offiziell)
7. 🔮 Vollständige Integration

---

## 📝 Verwendung

### Für Entwickler:

**BSI-Daten fetchen:**
```bash
python scripts/fetch_bsi_cert.py
```

**API testen:**
```bash
# Status
curl http://localhost:8001/api/v1/data-sources/bsi-cert/status

# Fetch triggern
curl -X POST http://localhost:8001/api/v1/data-sources/bsi-cert/fetch
```

### Für Benutzer:

**BSI-Informationen finden:**
1. Klick auf "🇩🇪 BSI" in der Navigation
2. Öffne BSI CERT-Bund Portal
3. Suche manuell nach CVE-ID

**BSI-Badge sehen:**
- Nur wenn CVE von BSI referenziert wird
- Erscheint automatisch im CVE-Header
- Zeigt offizielle BSI-Quelle an

---

## 🔗 Nützliche Links

- **BSI CERT-Bund Portal:** https://wid.cert-bund.de/portal/wid/securityadvisory
- **BSI RSS-Feed:** https://wid.cert-bund.de/content/public/securityAdvisory/rss
- **BSI Bürger-CERT:** https://wid.cert-bund.de/content/public/buergercert/rss

---

## ❓ FAQ

**Q: Warum sehe ich keine BSI-Badges?**
A: Weil der RSS-Feed keine CVE-IDs enthält. Diese müssen von den Detail-Seiten gescraped werden.

**Q: Wann wird das implementiert?**
A: Scraping ist komplex. Aktuell haben wir eine separate BSI-Seite mit manuellen Links.

**Q: Kann ich BSI-Daten manuell hinzufügen?**
A: Ja, über die API oder direkt in der Datenbank.

**Q: Gibt es eine offizielle BSI-API?**
A: Nein, nur RSS-Feed. Detail-Daten müssen gescraped werden.

---

---

## 📧 Support

Fragen oder Probleme? Kontaktiere uns:
- **Email:** hoodinformatik@gmail.com
- **GitHub:** https://github.com/hoodinformatik/OpenThreat

**Letzte Aktualisierung:** 2025-10-16
