# BSI CERT-Bund

InterCat Lynx übernimmt die Warnmeldungen des **BSI CERT-Bund** (Bundesamt für Sicherheit in der
Informationstechnik, Warn- und Informationsdienst „WID“) über den öffentlichen **CSAF-Feed** des BSI.

## Was kommt woher

| | |
|---|---|
| Anbieter-Beschreibung | `https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json` (Rolle `csaf_trusted_provider`) |
| Verwendeter Feed | `https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json` (ROLIE, Einstufung **TLP:WHITE**) |
| Nicht verwendet | die GREEN-Feeds (nicht für die Öffentlichkeit) und der CVD-Feed |
| Format | CSAF 2.0 (JSON); ROLIE = Liste der Dokumente mit Änderungsdatum |

## Was gespeichert wird (und was nicht)

Gespeichert werden nur Verzeichnisdaten: Nummer (z. B. `WID-SEC-W-2026-0042`), Titel, Einstufung
(kritisch/hoch/mittel/niedrig), Veröffentlichungs- und Änderungsdatum, CVE-Nummern, eine kurze Liste
betroffener Produkte und der Link zum Original. **Der Text der Meldung wird nicht gespeichert.** Jede
Anzeige verlinkt auf das BSI und nennt es als Quelle. Die BSI-Seite wird nicht gespiegelt.

## Wo es sichtbar ist

- Seite **BSI** in der Navigation: Liste mit Suche (Titel, Nummer, CVE) und Filter nach Einstufung.
- **CVE-Seite:** Abzeichen „BSI CERT-Bund“ und Abschnitt mit den Meldungen, die dieses CVE nennen.
- **Administration → Daten:** Karte „BSI CERT-Bund“ (Schalter, Stand, „Jetzt abrufen“) und Eintrag in den
  geplanten Aufgaben.

## Wie der Abruf läuft

- Aufgabe `tasks.fetch_bsi_csaf`, Zeitplan: alle 3 Stunden zur Minute 20 (Celery Beat).
- Der Feed wird bedingt abgefragt (ETag): ist er unverändert, kostet der Lauf eine kleine Anfrage.
- Erster Lauf: Meldungen der letzten 60 Tage. Danach ab dem letzten vollständigen Lauf minus 2 Tage.
- Höchstens 400 Dokumente je Lauf mit kurzer Pause dazwischen; der Rest folgt beim nächsten Lauf.
- Ein defektes Dokument bricht den Lauf nicht ab; der Startpunkt rückt dann aber nicht vor, der nächste Lauf
  versucht es erneut. Bereits gespeicherte, unveränderte Dokumente werden nicht noch einmal geladen.

## Sicherheit beim Abruf

Der Inhalt des Feeds sind Daten, keine Anweisungen. Deshalb gilt: nur `https`, nur der Host
`wid.cert-bund.de` (auch für jeden Link im Feed und für Weiterleitungen), Größenlimit je Antwort, Zeitlimits.
Fehlermeldungen im Bericht der geplanten Aufgaben nennen nur den Fehlertyp.

## Nutzungsbedingungen des BSI

Die [Nutzungsbedingungen des BSI](https://www.bsi.bund.de/DE/Service/Nutzungsbedingungen/Nutzungsbedingungen_node.html)
erlauben die freie Nutzung von BSI-Inhalten für **nicht kommerzielle**, rechtmäßige Zwecke zur Förderung der
IT-Sicherheit. Kommerzielle oder werbliche Nutzung braucht eine Vereinbarung mit dem BSI, das Spiegeln von
BSI-Internetinhalten die vorherige schriftliche Zustimmung. Die Metadaten des Feeds enthalten keine eigene
Lizenzangabe; das BSI erlaubt dort die Spiegelung durch CSAF-Aggregatoren
(`mirror_on_CSAF_aggregators: true`). Wer InterCat Lynx **kommerziell betreibt**, schaltet den Abruf ab oder
holt vorher die Zustimmung des BSI ein (Kontakt für CSAF: csaf@bsi.bund.de).

Weitere Regeln, an die sich die Anzeige hält: Quellennachweis, kein Eindruck einer Zusammenarbeit mit dem
BSI, kein Bundesadler-Logo.

## Einstellungen

| Schalter | Wirkung |
|---|---|
| Administration → Daten → „Abruf abschalten“ | speichert `bsi.enabled=false` in der Datenbank |
| Umgebungsvariable `BSI_ENABLED=false` | Voreinstellung, solange in der Datenbank nichts steht |

Reihenfolge wie bei allen Einstellungen: Datenbank vor Umgebungsvariable vor Voreinstellung (eingeschaltet).

## Schnittstellen

| Aufruf | Zugriff | Zweck |
|---|---|---|
| `GET /api/v1/bsi/advisories?page&page_size&severity&q` | öffentlich | Liste |
| `GET /api/v1/bsi/cve/{CVE-…}` | öffentlich | Meldungen zu einem CVE |
| `GET /api/v1/bsi/status` | Admin | Schalter, Stand, Anzahl |
| `PUT /api/v1/bsi/settings` | Admin | ein-/ausschalten (im Audit-Log) |
| `POST /api/v1/bsi/fetch` | Admin | Abruf sofort einreihen |

## Code

`backend/services/bsi_service.py` (Abruf, Auswertung, Speichern), `backend/api/bsi.py`,
`backend/tasks/data_tasks.py` (`fetch_bsi_csaf_task`), Migration `alembic/versions/017_bsi_advisories.py`,
Tests `tests/test_bsi.py`; Oberfläche `frontend/app/bsi/page.tsx`, `frontend/components/admin/BsiCard.tsx`,
`frontend/lib/bsi-api.ts`.
