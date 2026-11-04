# Geräteübergreifende Synchronisation einrichten

Ziel: du und dein Bruder seht denselben Datenstand. Dein Bruder braucht dafür
**nur die Adresse der Seite und die gemeinsame Passphrase** – keinen Account,
keine Zugangsdaten von dir.

Dazu läuft ein winziger **Cloudflare Worker** (Gratis-Tarif), der genau einen
verschlüsselten Datenblock speichert. Der Worker sieht nie Klartext.

Einmalig einzurichten – nur von dir, ~10 Minuten:

## 1. Cloudflare-Konto

Kostenloses Konto auf https://dash.cloudflare.com/sign-up anlegen (keine
Kreditkarte nötig).

## 2. Worker deployen

```bash
cd /Users/ylau/Yingway/worker

# Wrangler (Cloudflare-CLI) – einmalig
npm install -g wrangler        # oder jeden Befehl unten mit  npx  davor

wrangler login                 # öffnet den Browser, einmal bestätigen

# KV-Speicher anlegen – gibt eine id aus:
wrangler kv namespace create DB
# (ältere Wrangler-Versionen:  wrangler kv:namespace create DB )
```

Die ausgegebene `id` in `worker/wrangler.toml` bei `HIER_KV_NAMESPACE_ID_EINTRAGEN`
eintragen. Dann:

```bash
wrangler deploy
```

Am Ende steht eine URL, z. B.
`https://yingway-sync.deinname.workers.dev`

## 3. App auf den Worker zeigen

In `sync.config.js` (Repo-Wurzel) die URL eintragen – **mit `/vault` am Ende**:

```js
window.__SYNC_URL__ = "https://yingway-sync.deinname.workers.dev/vault";
```

Committen und pushen:

```bash
cd /Users/ylau/Yingway
git add sync.config.js && git commit -m "Sync aktivieren" && git push
```

## 4. Daten das erste Mal hochladen

1. https://yingsiulau.github.io/yingway/ öffnen
2. Passphrase festlegen (mind. 10 Zeichen – **diese** bekommt dein Bruder)
3. Übersicht → **Daten & Sicherung** → **Backup einspielen** → `seed.plain.json`
4. Bestätigen. Die Daten werden verschlüsselt in die Cloud geschoben
   (Statusanzeige „Sync ✓" unten links).

## 5. Bruder

Er öffnet dieselbe Adresse, gibt die Passphrase ein – fertig. Ab jetzt sehen
beide Geräte denselben Stand; Änderungen werden nach ~1 s abgeglichen und beim
Öffnen / Tab-Wechsel neu geladen.

---

## PDF-Belege aktivieren (optional)

Damit du bei Ein-/Ausgängen und laufenden Kosten einen PDF-Beleg anhängen und
sie gesammelt als ZIP herunterladen kannst, braucht der Worker zusätzlich
einen **R2-Bucket** (Cloudflare-Objektspeicher, Gratis-Tarif: 10 GB, keine
Transfergebühren). Belege werden – wie der Vault – im Browser AES-256-GCM
verschlüsselt hochgeladen; der Worker/R2 sieht nur Chiffretext.

Einmalig, nur von dir:

```bash
cd /Users/ylau/Yingway/worker
wrangler r2 bucket create yingway-files
wrangler deploy
```

`worker/wrangler.toml` hat den nötigen `[[r2_buckets]]`-Block schon (Binding
`FILES`, Bucket-Name `yingway-files`) – `wrangler deploy` reicht danach aus.
Kein Eintrag in `sync.config.js` nötig, die App erkennt R2 automatisch, sobald
`wrangler deploy` durch ist (Seite einmal neu laden).

In den Formularen erscheint dann bei Eingängen/Ausgängen/laufenden Kosten ein
Feld „Beleg (PDF)" (max. 15 MB), in der Tabelle ein kleines PDF-Symbol bei
Einträgen mit Anhang, und in der Übersicht die Karte **„Belege"** zum
gesammelten ZIP-Export nach Journal + Zeitraum.

---

## News (Shop-Monitor, optional)

Der Worker prüft reihum die Shops, die du in der App unter **News → Quellen**
einträgst (URL pro Zeile einfügen, auch viele auf einmal). Pro Shop wird auf
**Pokémon / One Piece / Dragon Ball** gefiltert und bei jeder Änderung gemeldet:
**neue Produkte**, **Preisänderungen** und **ausverkauft → wieder verfügbar**
(Dashboard unter *News*, auch via `…/yingway/#news`, plus je Meldung eine
Push-Nachricht). Neue Quellen merken sich beim ersten Lauf nur den aktuellen
Stand – keine Flut.

- **Unterstützt:** Shopify-Shops und WooCommerce-Shops (am besten die
  Kategorie-/Kollektions-URL, z. B. `https://cardtreasure.ch/collections/…`
  oder `https://www.nooks.ch/pokemon/`; die Shop-Startseite überwacht alle
  Produkte) sowie wog.ch. Andere Systeme (PrestaShop, Wix, JS-only-Seiten) meldet
  die App als „Shop-Typ nicht erkannt“ – dafür braucht es einen eigenen Adapter.
  Seiten, deren robots.txt das Abrufen von Verfügbarkeiten verbietet, werden nicht
  abgefragt.
- **Beobachten (einzelne Produkte):** In *News → Beobachten* einen Produkt-Link
  einfügen. Die App prüft ihn wie in einem Chat: bei einem Produkt mit Varianten
  fragt sie, welche gemeint ist; bei einer Kollektions-/Shop-Seite zeigt sie die
  neuesten Produkte zur Auswahl (oder „ganze Kollektion überwachen“); nicht
  unterstützte Links werden abgelehnt. Mit dem Häkchen wird die Beobachtung
  gespeichert, gemeldet werden Preisänderungen und „wieder verfügbar“. Funktioniert
  für Shopify-, WooCommerce-Produktseiten und wog.ch.
- **Franchises pro Quelle:** Beim Hinzufügen und später per **ändern** in der
  Quellen-Tabelle wählst du pro Shop, welche Franchises gemeldet werden
  (Pokémon, One Piece, Dragon Ball, Riftbound, Naruto, Cyberpunk, Magic, Yu-Gi-Oh!,
  Lorcana, Digimon, Star Wars, Flesh and Blood, Gundam, Union Arena). Nichts
  angehakt = **alle** Produkte der Quelle. Fehlt eins, legst du unter
  *Franchise hinzufügen* ein eigenes an (Name + optionale Stichwörter, die im
  Produkttitel/Typ/Hersteller gesucht werden). Eine Änderung liest die Quelle
  still neu ein – ohne Meldungs-Flut. Ist eine Kollektion schon per URL
  eingegrenzt (z. B. `…/pokemon`), wird beim Hinzufügen automatisch nicht
  gefiltert, weil die Titel dort das Wort oft nicht enthalten.
- **Takt:** Cron alle 5 Min.; pro Lauf werden so viele Quellen geprüft, wie das
  Budget (40 Anfragen, ~2,5 MB) erlaubt, die am längsten ungeprüften zuerst. Bei
  ~50 Shops ist ein voller Durchgang daher nach ca. 20–40 Min. durch. Auf dem
  bezahlten Workers-Plan ($5/Monat) kannst du `RUN_SUBREQ`/`RUN_BYTES` in
  `worker/worker.js` stark erhöhen, dann wird alles jede Runde geprüft.

Das Dashboard läuft schon nach `wrangler deploy` (der Cron ist in
`wrangler.toml` eingetragen). Für die **Mails** braucht es einmalig einen
Mail-API-Dienst (Resend, gratis: 100 Mails/Tag). Dein Bruder muss dafür
nichts deployen – er braucht nur ein Resend-Konto, und du hinterlegst
Key und seine Adresse im Worker:

1. **Bruder:** Konto auf https://resend.com mit **seiner Mail-Adresse** anlegen
   (ohne eigene Domain darf Resend nur an die Konto-Adresse senden), unter
   *API Keys* einen Key erstellen und dir schicken.
2. **Du:** Key und Empfänger im Worker hinterlegen (Secrets – bleiben aus dem
   öffentlichen Repo raus):

   ```bash
   cd /Users/ylau/Yingway/worker
   wrangler secret put RESEND_API_KEY     # Key einfügen, Enter
   wrangler secret put NEWS_TO            # Adresse deines Bruders
   wrangler deploy
   ```
3. In der App → **News** → **Testmail** (zeigt „Mail aktiv“, sobald beide Secrets da sind).

Beide sehen die Seite **News** mit URL + Passphrase, wie die restliche App.
Mehrere Empfänger: `NEWS_TO` kommagetrennt (nur mit bei Resend verifizierter
Domain, dann auch `NEWS_FROM` setzen). Die Filter-Stichwörter stehen in
`worker/worker.js` (`FRANCHISES`). Abfrage-Rücksicht: je Shop höchstens eine Abfrage
alle paar Minuten, ehrlicher User-Agent, nur öffentliche Produkt-Feeds.

---

## Als App installieren + Push-Benachrichtigungen (PWA)

Die Seite ist eine installierbare App (Manifest + Icons). Mit **Push** erscheint
eine Meldung auf dem Handy/Computer, sobald News anfallen; ein Tipp darauf öffnet
die App direkt auf der **News**-Seite (nach dem Entsperren mit der Passphrase –
die Daten bleiben Ende-zu-Ende verschlüsselt, in der Push-Nachricht stehen nur
Produktname und Preis).

Nach `wrangler deploy` (neuer Worker) und dem Seiten-Deploy, pro Gerät einmalig:

- **Android (Chrome):** Seite öffnen → Menü → *App installieren* (optional) →
  **News → Push aktivieren** → erlauben.
- **iPhone/iPad (ab iOS 16.4):** In **Safari** öffnen → Teilen →
  **Zum Home-Bildschirm** → die App **vom Home-Bildschirm** öffnen (nicht aus
  Safari!) → **News → Push aktivieren** → erlauben. In einem normalen Safari-Tab
  gibt es auf iOS keine Push-Meldungen.
- **Mac/PC (Chrome, Edge, Firefox):** Seite öffnen → **News → Push aktivieren**.

Mit **Test-Push** prüfst du, ob es ankommt. Jedes Gerät meldet sich einzeln an
(bis 8 Geräte); „Push aus“ meldet das aktuelle Gerät wieder ab. Die Schlüssel
(VAPID) erzeugt der Worker selbst beim ersten Mal, es ist kein Secret nötig.
Push ist der einzige Meldeweg; den früheren Mailversand über Resend gibt es
nicht mehr.

---

## Sicherheit & Grenzen

- **Ende-zu-Ende verschlüsselt**: der Worker speichert nur AES-256-GCM-Chiffretext.
  Ohne Passphrase ist nichts lesbar. Jede Anfrage muss ein aus der Passphrase
  abgeleitetes Token (SHA-256) mitschicken – der Worker kennt davon nur den Hash.
- **Kein echtes 2FA** – bei statischem Hosting technisch nicht möglich. Sicherheit
  = Stärke der Passphrase. Nimm eine lange (4–5 Wörter).
- **Konflikt**: ändern beide *gleichzeitig* auf verschiedenen Geräten, gewinnt der
  erste Schreibvorgang; das andere Gerät zeigt „Konflikt" + „Neu laden". Bei
  abwechselnder Nutzung passiert das praktisch nie.
- **KV ist eventual consistent**: nach einer Änderung kann es bis ~60 s dauern,
  bis ein anderes Gerät sie sieht.
- Kosten: Cloudflare-Gratis-Tarif (100 000 Anfragen/Tag) reicht um Grössenordnungen.
- Passphrase wechseln: geht in der App, aber der andere muss die neue dann auch
  eingeben (steht als Warnung dabei).
