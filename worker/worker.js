/*
 * YL Sync – Cloudflare Worker
 *
 * Speichert genau EINEN verschlüsselten Datenblock ("vault") in KV, plus
 * optional verschlüsselte PDF-Belege in einem R2-Bucket. Der Worker sieht
 * nie Klartext: alles, was er entgegennimmt, ist bereits AES-256-GCM-
 * verschlüsselt (mit der Passphrase, die nur im Browser existiert).
 *
 * Zugriff: jede Anfrage muss  Authorization: Bearer <token>  mitschicken.
 *   token = SHA-256("yingway|" + passphrase)   (im Browser berechnet)
 * Der Worker kennt nur SHA-256(token) und kann daraus die Passphrase
 * nicht zurückrechnen. Wer die Passphrase kennt, darf lesen + schreiben,
 * sonst niemand.
 *
 * Endpunkte:
 *   GET  /vault                -> { rev, blob, updatedAt }   (blob=null wenn leer)
 *   PUT  /vault                Body { blob, baseRev }
 *                              -> 200 { rev, updatedAt }
 *                              -> 409 { error:"conflict", rev, blob }  (anderes Gerät war schneller)
 *                              -> 403  falsche Passphrase für vorhandene Daten
 *
 *   GET    /files/<ledger>/<id>  -> rohe verschlüsselte Bytes (PDF-Beleg)
 *   PUT    /files/<ledger>/<id>  Body = rohe verschlüsselte Bytes  -> 200 {ok:true}
 *   DELETE /files/<ledger>/<id>                                    -> 200 {ok:true}
 *   Belege gehören zu einem bereits beanspruchten Vault – ohne beanspruchten
 *   Vault (siehe oben) lehnt /files jede Anfrage ab.
 *
 * News-Monitor: ein Cron-Trigger (alle 5 Min.) prüft reihum die in der App eingetragenen
 * Shops (Shopify, WooCommerce, Shopware, PrestaShop, ePages, CS-Cart, SumUp, JSON-LD und wog.ch), filtert auf Pokémon / One Piece / Dragon Ball,
 * vergleicht mit dem letzten Stand und meldet per Web-Push: neue Produkte,
 * Preisänderungen, ausverkauft -> wieder verfügbar.
 *   GET    /news                -> { sources, events, lastRun, lastError, push }
 *   POST   /news/check          Body { ids? }  -> Prüfrunde sofort (ohne ids: volle Runde wie der Cron)
 *   POST   /news/sources        Body { urls:[…≤8], filter }  -> Quellen hinzufügen (Typ wird erkannt)
 *   PUT    /news/sources/<id>   Body { name?, off?, filter? }
 *   DELETE /news/sources/<id>
 *   GET /news/push/key · POST /news/push {sub} · POST /news/push/remove {endpoint} · POST /news/push/test
 *             -> Web-Push (PWA): Geräte anmelden, Test senden
 *   Gleiche Passphrase-Auth wie /files. Gemeldet wird per Push; ohne angemeldetes
 *   Gerät läuft nur das Dashboard. (Der frühere Mailversand über Resend ist raus.)
 */

const KV_KEY = 'vault';
const CFG_KEY = 'watch:cfg';
const STATE_KEY = 'watch:state';
const MAX_FILE_BYTES = 20 * 1024 * 1024;

const WOG_LIST = 'https://www.wog.ch/de/index.cfm/ajax.productList';
const WATCH_UA = 'Mozilla/5.0 (compatible; YLMonitor/1.0; +https://ylau802.github.io/Buchhaltung-TCG/)';
// Antworten, mit denen ein Shop automatische Abrufe abweist. Neben den ueblichen
// 401/403/429 gehoert 510 dazu: so meldet sich die Firewall von
// thesecretcardshop.ch ("Access denied by security policy"), und 451 und 406
// benutzen andere Schutzmodule fuer dasselbe.
const BLOCKED = /HTTP (401|403|406|429|451|510)/;
const MAX_SOURCES = 400;
const MAX_PAGES = 4;          // Shopify: bis 4 x 250 Produkte pro Kollektion
// Seiten je Durchlauf: [schnell, vollstaendig]. Schnell laeuft jede Runde und deckt
// die neuesten Artikel ab (die Listen sind nach "Neuste zuerst" sortiert), der volle
// Durchlauf kommt einmal pro Stunde und findet auch Preis- und Bestandsaenderungen
// weiter hinten. Shops mit grossen Seiten brauchen keine Staffelung.
const PAGE_BUDGET = {
  wix: [1, 4],
  shopify: [4, 4],        // 250 Artikel je Seite
  woocommerce: [4, 4],    // 100 je Seite
  epages: [3, 6],         // 100 je Seite
  wog: [1, 1],
  // cscart und sumup laufen ueber WINDOW, nicht ueber diese Tabelle
};
const FULL_EVERY = 50 * 60 * 1000;   // voller Durchlauf hoechstens stuendlich
// Shops ohne Schnittstelle liefern wenige Artikel je Seite und viel Drumherum. Statt
// einmal pro Stunde durch die ganze Kategorie zu rauschen (was goodgamesbern.ch mit
// HTTP 403 quittiert hat), steht Seite 1 in jedem Lauf – dort erscheinen neue Artikel –
// und dazu ein Fenster weiter hinten, das mit jedem Lauf weiterwandert. Nach ein paar
// Laeufen war die ganze Kategorie dran, ohne je mehr als drei Seiten am Stueck zu holen.
const WINDOW = { cscart: 1, sumup: 2, shopware: 1, prestashop: 2, jsonld: 1 };
const COOL_AFTER_BLOCK = 30 * 60 * 1000;  // nach der ersten Sperre; danach jeweils doppelt
const COOL_MAX = 6 * 60 * 60 * 1000;      // laenger als sechs Stunden warten wir nie
const HOST_PAGES = 4;                // so viele Seiten je Shop und Lauf, mehr nicht
const HOST_PAUSE = 2000;             // Pause zwischen zwei Anfragen an denselben Shop
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const EVENTS_KEEP = 500;
// Pro Cron-Lauf: Workers-Limit sind 50 Anfragen; das Datenbudget hält die CPU-Zeit klein (Free-Tarif).
const RUN_SUBREQ = 40;
const RUN_BYTES = 12000000;  // entpackt; CS-Cart ~1 MB, Shopware ~3 MB je Seite

function corsHeaders(extra) {
  return Object.assign({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Cache-Control': 'no-store',
  }, extra || {});
}
const json = (obj, status) =>
  new Response(JSON.stringify(obj), { status: status || 200, headers: corsHeaders({ 'Content-Type': 'application/json' }) });
const text = (msg, status) =>
  new Response(msg, { status: status || 200, headers: corsHeaders() });

async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function readVault(env) {
  const stored = await env.DB.get(KV_KEY);
  return stored ? JSON.parse(stored) : null;
}

async function handleVault(request, env, tokenHash) {
  const rec = await readVault(env);
  if (rec && rec.tokenHash !== tokenHash) return text('forbidden', 403);

  if (request.method === 'GET') {
    if (!rec) return json({ rev: 0, blob: null });
    return json({ rev: rec.rev, blob: rec.blob, updatedAt: rec.updatedAt });
  }
  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    if (!body || typeof body.blob !== 'string' || body.blob.length < 16)
      return text('bad body', 400);
    if (body.blob.length > MAX_FILE_BYTES) return text('too large', 413);

    const curRev = rec ? rec.rev : 0;
    const baseRev = Number(body.baseRev || 0);
    if (baseRev !== curRev)
      return json({ error: 'conflict', rev: curRev, blob: rec ? rec.blob : null }, 409);

    const next = { blob: body.blob, rev: curRev + 1, updatedAt: new Date().toISOString(), tokenHash };
    await env.DB.put(KV_KEY, JSON.stringify(next));
    return json({ rev: next.rev, updatedAt: next.updatedAt });
  }
  return text('method not allowed', 405);
}

async function handleFiles(request, env, url, tokenHash) {
  if (!env.FILES) return text('R2-Bucket "FILES" fehlt (siehe SETUP-SYNC.md)', 500);

  const rec = await readVault(env);
  if (!rec) return text('kein Vault angelegt', 409);
  if (rec.tokenHash !== tokenHash) return text('forbidden', 403);

  const key = decodeURIComponent(url.pathname.slice('/files/'.length));
  if (!key || key.includes('..') || key.split('/').length !== 2) return text('bad key', 400);

  if (request.method === 'GET') {
    const obj = await env.FILES.get(key);
    if (!obj) return text('not found', 404);
    return new Response(obj.body, {
      headers: corsHeaders({ 'Content-Type': 'application/octet-stream', 'Content-Length': String(obj.size) }),
    });
  }
  if (request.method === 'PUT') {
    const len = Number(request.headers.get('Content-Length') || 0);
    if (len > MAX_FILE_BYTES) return text('too large', 413);
    await env.FILES.put(key, request.body, { httpMetadata: { contentType: 'application/octet-stream' } });
    return json({ ok: true });
  }
  if (request.method === 'DELETE') {
    await env.FILES.delete(key);
    return json({ ok: true });
  }
  return text('method not allowed', 405);
}

// ---------- News-Monitor (viele Shops) ----------
//
// Konfiguration (Liste der Quellen) und Zustand (Schnappschüsse, Ereignisse, Status) liegen in
// getrennten KV-Einträgen: der Cron schreibt nur den Zustand, die App nur die Konfiguration.

const chf = (v) => (v == null ? 'Preis folgt' : 'CHF ' + Number(v).toFixed(2));
// Preis aus sichtbarem Text ("CHF 2'299.95", "49,90 CHF"). Zuerst die Entities
// aufloesen: Shops schreiben das Tausender-Hochkomma gern als &#x27; oder &#039;,
// und wer das stehen laesst, liest aus "CHF 2&#x27;299.95" glatt 299.95 heraus.
// Danach Hochkommas und Leerzeichen weg, erst dann die Zahl suchen.
const textPrice = (s) => {
  // Was nach dem Aufloesen noch wie eine Entity aussieht, fliegt raus: ein
  // uebriggebliebenes "&xyz;" mitten in der Zahl waere schlimmer als gar keines.
  const t = decodeEntities(String(s == null ? '' : s))
    .replace(/&[#a-z0-9]+;/gi, '').replace(/[\u2019\u2018'\u00a0\s]/g, '');
  const m = t.match(/(\d+(?:[.,]\d{1,2})?)/);
  if (!m) return null;
  const n = parseFloat(m[1].replace(',', '.'));
  return n > 0 ? n : null;
};
// Franchise-Katalog: eingebaute + eigene (cfg.customFr = [{ name, kw: [Stichwörter] }]).
// Pro Quelle wählt man, welche gemeldet werden (src.fr); leer = alle Produkte.
const BUILTIN_FR = [
  ['Pokémon', /pok[eé]mon|\bpkm\b/i], ['One Piece', /one[\s\-_]*piece/i], ['Dragon Ball', /dragon[\s\-_]*ball/i],
  ['Riftbound', /riftbound/i], ['Naruto', /naruto/i], ['Cyberpunk', /cyberpunk/i],
  ['Magic', /\bmagic\b|\bmtg\b/i], ['Yu-Gi-Oh!', /yu[\s\-_]*gi[\s\-_]*oh/i], ['Lorcana', /lorcana/i], ['Digimon', /digimon/i],
  ['Star Wars', /star[\s\-_]*wars/i], ['Flesh and Blood', /flesh[\s\-_]*(and|&)[\s\-_]*blood/i], ['Gundam', /gundam/i], ['Union Arena', /union[\s\-_]*arena/i],
];
const DEFAULT_FR = ['Pokémon', 'One Piece', 'Dragon Ball'];
const kwRegex = (kw) => new RegExp(kw.map((k) => String(k).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '[\\s\\-_]*')).filter(Boolean).join('|') || '$^', 'i');
let CATALOG = BUILTIN_FR.slice();
const setCatalog = (cfg) => { CATALOG = BUILTIN_FR.concat((cfg.customFr || []).map((c) => [c.name, kwRegex(c.kw)])); };
const franchiseOf = (hay) => (CATALOG.find(([, re]) => re.test(hay)) || [''])[0];
// Sprache des Artikels. Die Shops schreiben sie entweder in den Namen
// ("… - englisch", "-EN-", "Kollektion DE") oder nur in den Link
// ("…-booster-box-franzoesisch"). Kürzel zählen nur in Grossbuchstaben, sonst
// gäbe das "de" in einer Shop-Adresse oder das französische "de" in einem Titel
// eine falsche Sprache.
// Einzelbuchstaben wie "-D-" zählen nur freistehend, sonst trifft es "Mega-D-Luxe".
const LANGS = [
  ['EN', /englisch|english|anglais|inglese/i, /(^|[^A-Za-z0-9])(EN|ENG)([^A-Za-z0-9]|$)|(?:^|\s)-E-(?=\s|$)/],
  ['DE', /deutsch|german|allemand|tedesco/i, /(^|[^A-Za-z0-9])(DE|GER|DEU)([^A-Za-z0-9]|$)|(?:^|\s)-D-(?=\s|$)/],
  ['FR', /franz(ö|oe)sisch|french|fran(ç|c)ais/i, /(^|[^A-Za-z0-9])(FR|FRA)([^A-Za-z0-9]|$)|(?:^|\s)-F-(?=\s|$)/],
  ['IT', /italienisch|italian|italiano/i, /(^|[^A-Za-z0-9])(IT|ITA)([^A-Za-z0-9]|$)|(?:^|\s)-I-(?=\s|$)/],
  ['JP', /japanisch|japanese|japonais|japan\b/i, /(^|[^A-Za-z0-9])(JP|JPN|JAP)([^A-Za-z0-9]|$)|(?:^|\s)-J-(?=\s|$)/],
  ['CN', /chinesisch|chinese/i, /(^|[^A-Za-z0-9])(CN|CHS|CHT)([^A-Za-z0-9]|$)/],
  ['KR', /koreanisch|korean/i, /(^|[^A-Za-z0-9])(KR|KOR)([^A-Za-z0-9]|$)/],
  ['ES', /spanisch|spanish|espa(ñ|n)ol/i, /(^|[^A-Za-z0-9])(ES|ESP)([^A-Za-z0-9]|$)/],
  ['PT', /portugiesisch|portuguese|portugu(ê|e)s/i, /(^|[^A-Za-z0-9])(PT|POR)([^A-Za-z0-9]|$)/],
];
const urlPath = (u) => { try { return decodeURIComponent(new URL(u).pathname); } catch (e) { return ''; } };
const urlSlug = (u) => urlPath(u).replace(/\/+$/, '').split('/').pop();
function langIn(s) {
  let best = null;
  for (const [code, word, abbr] of LANGS) {
    const m = s.match(word) || s.match(abbr);
    if (m && (best === null || m.index < best[1])) best = [code, m.index];
  }
  return best ? best[0] : '';
}
// Was am Artikel steht, schlägt den Link; der Link schlägt die Kategorie der Quelle
// (so bekommt z. B. die Kollektion "englische-pokemon-karten" ihre Sprache).
const langOf = (title, url, srcUrl) =>
  langIn(title || '') || langIn(urlSlug(url || '')) || langIn(urlPath(srcUrl || '')) || '';
const srcFr = (s) => (Array.isArray(s.fr) ? s.fr : s.filter === false ? [] : DEFAULT_FR);
const passes = (src, hay) => { const fr = srcFr(src); return !fr.length || CATALOG.some(([n, re]) => fr.includes(n) && re.test(hay)); };
const resetSource = (st, id) => { if (st.src[id]) delete st.src[id].init; delete st.snap[id]; }; // stilles Neu-Einlesen

const DEFAULT_SOURCES = [{ id: 'wog', name: 'World of Games', url: 'https://www.wog.ch/de/index.cfm/lastAdded/platform/Trading-Cards', type: 'wog', fr: DEFAULT_FR.slice() }];

async function readCfg(env) {
  const s = await env.DB.get(CFG_KEY);
  const cfg = s ? JSON.parse(s) : { sources: DEFAULT_SOURCES.slice() };
  setCatalog(cfg);
  return cfg;
}
async function readState(env) {
  const s = await env.DB.get(STATE_KEY);
  return s ? JSON.parse(s) : { snap: {}, src: {}, events: [] };
}

// Alle Adapter liefern [{ id, t, p, a, u, i, g }]: Titel, Preis, verfügbar (0/1), Link, Bild, Franchise.
async function getJson(url, init) {
  const opt = Object.assign({ headers: { 'User-Agent': WATCH_UA, Accept: 'application/json' } }, init || {});
  let res = await fetch(url, opt);
  if (res.status === 429) {           // gedrosselt: einmal kurz warten und erneut versuchen
    const ra = Number(res.headers.get('Retry-After'));
    await new Promise((r) => setTimeout(r, Math.min(ra > 0 ? ra * 1000 : 2000, 5000)));
    res = await fetch(url, opt);
  }
  if (!res.ok) throw new Error(new URL(url).host + ': HTTP ' + res.status);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { throw new Error(new URL(url).host + ': keine JSON-Antwort'); }
  return { data, bytes: text.length };
}

function shopifyApi(src) {
  const u = new URL(src.url);
  // Sprachpraefix wie /de-ch/ oder /en/ gehoert zum Pfad und bleibt stehen. Shopify
  // schreibt es mal klein (de-ch), mal gross (de-CH) – ohne das i blieb die Kollektion
  // unerkannt und es wurde der ganze Shop geprueft statt nur dieser Kollektion.
  const m = u.pathname.match(/^(\/[a-z]{2}(?:-[a-z]{2})?)?\/collections\/([^/]+)/i);
  return u.origin + (m ? (m[1] || '') + '/collections/' + m[2] : '') + '/products.json';
}
const shopifyImg = (src) => (src ? src.replace(/(\.\w+)(\?.*)?$/, '_150x$1$2') : '');

async function fetchShopify(src, max) {
  const base = shopifyApi(src), origin = new URL(src.url).origin;
  const out = [];
  let pages = 0, bytes = 0, truncated = false;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    const { data, bytes: b } = await getJson(base + '?limit=250&page=' + page);
    pages++; bytes += b;
    const list = data.products;
    if (!Array.isArray(list)) throw new Error(new URL(base).host + ': kein Shopify-Shop');
    for (const p of list) {
      const prices = (p.variants || []).map((v) => parseFloat(v.price)).filter((x) => x >= 0);
      const tagStr = Array.isArray(p.tags) ? p.tags.join(' ') : String(p.tags || '');
      const hay = [p.title, p.product_type, p.vendor, tagStr].join(' ');
      if (!passes(src, hay)) continue;
      out.push({
        id: String(p.id), t: p.title,
        p: prices.length ? Math.min(...prices) : null,
        a: (p.variants || []).some((v) => v.available) ? 1 : 0,
        u: origin + '/products/' + p.handle,
        i: shopifyImg(p.images && p.images[0] && p.images[0].src),
        g: franchiseOf(hay),
      });
    }
    if (list.length < 250) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

async function fetchWog(src) {
  const { data, bytes } = await getJson(WOG_LIST, {
    method: 'POST',
    headers: {
      'User-Agent': WATCH_UA, Accept: 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Referer': 'https://www.wog.ch/de/index.cfm/lastAdded/platform/Trading-Cards',
    },
    body: 'listType=lastAdded&platform=Trading-Cards&maxRows=48&page=1',
  });
  if (!Array.isArray(data.products)) throw new Error('wog.ch: unerwartetes Antwortformat');
  const list = data.products
    .filter((p) => passes(src, p.title || p.fullTitle || ''))
    .map((p) => ({
      id: String(p.productID), t: p.fullTitle || p.title,
      p: p.unitPrice > 0 ? p.unitPrice : null,
      a: p.deliveryClass === 'circle-grey' ? 0 : 1,
      u: p.linkTo,
      i: p.coverSmallImage ? 'https://www.wog.ch' + p.coverSmallImage : '',
      g: franchiseOf(p.fullTitle || p.title || ''),
    }));
  return { list, pages: 1, bytes };
}

// WooCommerce (öffentliche Store-API): Kategorie-URL -> Kategorie-ID, dann Produkte seitenweise.
const wooApi = (src) => new URL(src.url).origin + '/wp-json/wc/store/v1';
const decodeEntities = (t) => String(t || '')
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))   // &#xE9; = é
  .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
  .replace(/&(amp|lt|gt|quot|nbsp|apos|rsquo|lsquo|ndash|mdash);/g, (_, k) =>
    ({ amp: '&', lt: '<', gt: '>', quot: '"', nbsp: ' ', apos: "'", rsquo: '\u2019', lsquo: '\u2018', ndash: '\u2013', mdash: '\u2014' }[k]));
const trimSlash = (p) => decodeURIComponent(p).replace(/\/+$/, '');

async function wooCategoryId(src) {
  const path = trimSlash(new URL(src.url).pathname);
  if (!path || /^\/(shop|produkte|products)$/i.test(path)) return null; // ganzer Shop
  try {
    for (let page = 1; page <= 3; page++) {
      const { data } = await getJson(wooApi(src) + '/products/categories?per_page=100&page=' + page);
      if (!Array.isArray(data)) break;
      const c = data.find((x) => trimSlash(new URL(x.permalink).pathname) === path);
      if (c) return { id: c.id, name: decodeEntities(c.name) };
      if (data.length < 100) break;
    }
  } catch (e) {
    // Manche Laeden sperren die Kategorie-Liste (theuncommonshop.ch antwortet mit 403).
    // Die Produktliste nimmt aber auch den Kurznamen aus der Adresse statt der Nummer.
    // Einmal nachfragen, ob damit wirklich etwas kommt - sonst stuende hier spaeter
    // eine Quelle, die stillschweigend nichts findet.
    const slug = path.split('/').filter(Boolean).pop() || '';
    if (slug) {
      const { data } = await getJson(wooApi(src) + '/products?per_page=1&category=' + encodeURIComponent(slug));
      if (Array.isArray(data) && data.length) return { id: slug, name: slug };
    }
  }
  throw new Error('Kategorie nicht gefunden (URL der Kategorie-Seite verwenden)');
}

function wooNorm(p) {
  const hay = [p.name, ...(p.categories || []).map((c) => c.name), ...(p.tags || []).map((c) => c.name)].map(decodeEntities).join(' ');
  const pr = p.prices && p.prices.price !== '' && p.prices.price != null ? Number(p.prices.price) / Math.pow(10, p.prices.currency_minor_unit == null ? 2 : p.prices.currency_minor_unit) : null;
  return {
    id: String(p.id), t: decodeEntities(p.name), p: pr,
    a: p.is_in_stock ? 1 : 0, u: p.permalink,
    i: (p.images && p.images[0] && (p.images[0].thumbnail || p.images[0].src)) || '',
    g: franchiseOf(hay), hay,
  };
}

async function fetchWoo(src, max) {
  const out = [];
  let pages = 0, bytes = 0, truncated = false, per = 100;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    let data, b;
    try {
      ({ data, bytes: b } = await getJson(wooApi(src) + '/products?per_page=' + per + '&page=' + page
        + (src.cat ? '&category=' + encodeURIComponent(src.cat) : '')));
    } catch (e) {
      // Manche Laeden lassen hundert Artikel auf einen Schlag nicht zu und antworten
      // mit 403 (theuncommonshop.ch tut das, fuenfzig gehen dort anstandslos).
      // Dann eben in kleineren Haeppchen weiter - einmal, danach gilt der Fehler.
      if (per === 100 && /HTTP 403/.test(e.message)) { per = 50; pages++; page--; continue; }
      throw e;
    }
    pages++; bytes += b;
    if (!Array.isArray(data)) throw new Error(new URL(src.url).host + ': kein WooCommerce-Shop');
    for (const p of data) {
      const it = wooNorm(p);
      if (!passes(src, it.hay)) continue;
      delete it.hay; out.push(it);
    }
    if (data.length < per) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

// ePages Now (z. B. calandamagic.ch): die Seite ist eine React-App, die Produkte
// kommen aber aus einer offenen JSON-Schnittstelle:
//   /api/v2/products?categoryId=<GUID>&resultsPerPage=100&page=1
// Die GUID der Kategorie steht nur im eingebetteten Zustand der Kategorieseite
// (window.__EP, Feld storeInitialState) – die wird einmal beim Anlegen gelesen.
const epagesApi = (src) => new URL(src.url).origin + '/api/v2/products';

function epagesState(html) {
  const m = html.match(/storeInitialState:\s*"((?:[^"\\]|\\.)*)"/);
  if (!m) return null;
  try { return JSON.parse(JSON.parse('"' + m[1] + '"')); } catch (e) { return null; }
}

function epagesNorm(p, origin) {
  const hay = [p.name, p.sku, (p.labels || []).map((l) => (l && l.name) || l).join(' ')].join(' ');
  let img = (p.image && p.image.url) || '';
  if (img && !/^https?:/.test(img)) img = origin + img;
  if (img) img += (img.includes('?') ? '&' : '?') + 'width=150&height=150';
  return {
    id: String(p.productId), t: p.name,
    // available deckt "Auf Lager" und "Jetzt vorbestellen" ab, false ist "Nicht auf Lager"
    p: p.price && p.price.amount >= 0 ? p.price.amount : null,
    a: p.available ? 1 : 0,
    u: origin + '/p/' + p.slug,
    i: img, g: franchiseOf(hay), hay,
  };
}

async function fetchEpages(src, max) {
  const base = epagesApi(src), origin = new URL(src.url).origin;
  const out = [];
  let pages = 0, bytes = 0, truncated = false;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    const { data, bytes: b } = await getJson(base + '?resultsPerPage=100&page=' + page + (src.cat ? '&categoryId=' + src.cat : ''));
    pages++; bytes += b;
    const list = data && data.products;
    if (!Array.isArray(list)) throw new Error(new URL(src.url).host + ': kein ePages-Shop');
    for (const p of list) {
      const it = epagesNorm(p, origin);
      if (!passes(src, it.hay)) continue;
      delete it.hay; out.push(it);
    }
    if (list.length < 100 || page * 100 >= Number(data.totalNumberOfProducts || 0)) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

// Kategorieseite -> { id, name, shop }. id = null bedeutet "ganzer Shop".
// Gibt null zurueck, wenn die Seite kein ePages-Shop ist.
function epagesFromHtml(pathname, html) {
  const st = epagesState(html);
  if (!st) return null;
  const shopName = (st.shop && (st.shop.title || st.shop.name)) || '';
  const cm = decodeURIComponent(pathname).match(/^\/c\/(.+?)\/*$/);
  if (!cm) return { id: null, name: '', shop: shopName };
  const id = (st.categorySlugsToGUIDs || {})[cm[1]];
  if (!id) throw new Error('Kategorie nicht gefunden (URL der Kategorie-Seite verwenden)');
  const cat = (st.categories || {})[id];
  return { id, name: (cat && cat.title) || cm[1], shop: shopName };
}

// CS-Cart (z. B. goodgamesbern.ch): keine offene Schnittstelle, aber sehr
// regelmaessiges HTML – je Produkt ein <form name="product_form_<id>">, darin
// Titel, Preis (verstecktes Feld) und Lagerzustand. Die Liste ist nach "Neuste
// zuerst" sortiert, darum reichen fuer einen News-Monitor die ersten Seiten.
const CS_MAX_PAGES = 2;
// Query gehoert dazu: die Liste "Neueste" ist index.php?dispatch=products.newest
const csClean = (u) => { const x = new URL(u); return x.origin + x.pathname + (x.search || ''); };
const stripTags = (s) => decodeEntities(String(s || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim());
const isCsCart = (html) => /name="product_form_\d+"/.test(html) && /\[price\]" value=/.test(html);

function csItems(html, origin) {
  const out = [];
  const parts = html.split(/name="product_form_(\d+)"/);
  for (let k = 1; k < parts.length; k += 2) {
    const id = parts[k], blk = parts[k + 1];
    const m = (re) => { const x = blk.match(re); return x ? x[1] : ''; };
    const t = decodeEntities(m(/class="product-title"[^>]*title="([^"]*)"/));
    let u = m(/<a href="([^"]+)" class="product-title"/);
    if (!t || !u) continue;                      // kein Listeneintrag (z. B. Warenkorb-Formular)
    if (!/^https?:/.test(u)) u = origin + (u.startsWith('/') ? '' : '/') + u;
    const price = parseFloat(m(new RegExp('product_data\\[' + id + '\\]\\[price\\]" value="([\\d.]+)"')));
    const img = m(new RegExp('id="det_img_' + id + '[a-z]*"[^>]*src="([^"]+)"'));
    out.push({
      id, t, p: price > 0 ? price : null,
      a: blk.includes('out_of_stock_info_' + id) ? 0 : 1,
      u, i: img, g: franchiseOf(t + ' ' + u),
    });
  }
  return out;
}

// Seite 2 heisst /pokemon/page-2/. Listen mit Query (z. B. "Neueste") haben nur eine Seite.
function csPageUrl(base, n) {
  const u = new URL(base);
  if (n <= 1 || u.search) return base;
  return u.origin + u.pathname.replace(/\/+$/, '') + '/page-' + n + '/';
}

async function fetchCs(src, plan) {
  const origin = new URL(src.url).origin, base = csClean(src.url);
  const want = Array.isArray(plan) && plan.length ? plan : [1];
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, firstCount = 0, end = false;
  for (const p of want) {
    if (p > 1 && new URL(base).search) { end = true; break; }   // nur eine Seite vorhanden
    if (pages) await sleep(HOST_PAUSE);   // je Seite ein Megabyte – nicht am Stueck anfordern
    let html, b;
    try { ({ html, bytes: b } = await getHtml(csPageUrl(base, p))); }
    catch (e) {
      if (p > 1 && /HTTP 404/.test(e.message)) { end = true; break; }   // hinter der letzten Seite
      throw e;
    }
    pages++; bytes += b;
    const list = csItems(html, origin);
    if (!list.length) {
      if (p === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      end = true; break;
    }
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      if (passes(src, it.t + ' ' + it.u)) out.push(it);
    }
    if (p === 1) firstCount = out.length;
  }
  return { list: out, pages, bytes, firstCount, end };
}

// Produktseite: das erste Formular gehoert zum Produkt selbst, danach kommen
// nur noch Zubehoer- und Empfehlungsblöcke.
function csProduct(html, url) {
  const id = (html.match(/name="product_form_(\d+)"/) || [])[1];
  const t = stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1]);
  if (!id || !t) throw new Error('Produktseite nicht lesbar');
  const price = parseFloat((html.match(new RegExp('product_data\\[' + id + '\\]\\[price\\]" value="([\\d.]+)"')) || [])[1]);
  const u = (html.match(/rel="canonical" href="([^"]+)"/) || [])[1] || csClean(url);
  return {
    id, pid: id, t, p: price > 0 ? price : null,
    a: html.includes('out_of_stock_info_' + id) ? 0 : 1,
    u, i: ((html.match(/og:image" content="\s*([^"]+)"/) || [])[1] || '').trim(),
    g: franchiseOf(t + ' ' + u),
  };
}

function csFromHtml(html) {
  if (!isCsCart(html)) return null;
  const site = (html.match(/"@type":\s*"WebSite"[\s\S]{0,300}?"name":\s*"([^"]+)"/) || [])[1] || '';
  return { shop: decodeEntities(site), name: stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1]) };
}

// SumUp Online Store (z. B. metagames.ch): Next.js-Shop, die Liste steht fertig
// im HTML. Jede Karte ist ein <a data-analytics="product-list-item"> mit id,
// Name, Link, Bild und Preis; "Ausverkauft" haengt als Label in der Karte.
// 16 Produkte je Seite, darum wird die Liste nach "Neuste zuerst" sortiert.
const SU_MAX_PAGES = 3;
const SU_PER_PAGE = 16;   // fest, der Shop kennt keinen Parameter dafuer
const isSumUpList = (html) => /data-analytics="product-list-item"/.test(html);
const isSumUpProduct = (html) => /data-selector="os-theme-product-title"/.test(html);

const suPrice = textPrice;

function suItems(html) {
  const out = [];
  const cards = html.split('<a data-analytics="product-list-item"');
  for (let i = 1; i < cards.length; i++) {
    const e = cards[i].indexOf('</a>');
    const c = cards[i].slice(0, e > 0 ? e : 4000);
    const m = (re) => { const x = c.match(re); return x ? x[1] : ''; };
    const id = m(/data-item-id="([^"]+)"/);
    const t = decodeEntities(m(/data-item-name="([^"]*)"/));
    const u = m(/href="([^"]+)"/);
    if (!id || !t || !u) continue;
    out.push({
      id, t,
      p: suPrice(m(/os-theme-product-list-price-regular"[^>]*>([^<]*)</)),
      a: c.includes('product-sold-out-label') ? 0 : 1,
      u, i: m(/<img[^>]+src="(https:\/\/images\.sumup\.com\/[^"]+)"/),
      g: franchiseOf(t),
    });
  }
  return out;
}

// Seite 1 ohne page-Parameter; die Sortierung wird erzwungen, sonst steht die
// Liste alphabetisch und ein News-Monitor sieht nie etwas Neues.
function suPageUrl(raw, page) {
  const u = new URL(raw);
  if (!u.searchParams.get('sortField')) {
    u.searchParams.set('sortField', 'createdAt');
    u.searchParams.set('sortDirection', 'desc');
  }
  if (page > 1) u.searchParams.set('page', String(page)); else u.searchParams.delete('page');
  return u.toString();
}

async function fetchSumup(src, plan) {
  const want = Array.isArray(plan) && plan.length ? plan : [1];
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, firstCount = 0, end = false;
  for (const p of want) {
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(suPageUrl(src.url, p));
    pages++; bytes += b;
    const list = suItems(html);
    if (!list.length) {
      if (p === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      end = true; break;
    }
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      if (passes(src, it.t + ' ' + it.u)) out.push(it);
    }
    // rel="next" steht bei SumUp auf jeder Seite, auch auf leeren – nur eine volle Seite
    // ist ein Hinweis darauf, dass es weitergeht.
    if (list.length < SU_PER_PAGE) { end = true; break; }
    if (p === 1) firstCount = out.length;
  }
  if (want[0] === 1 && !firstCount) firstCount = out.length;
  return { list: out, pages, bytes, firstCount, end };
}

// Produktseite: SumUp liefert dort JSON-LD (Product + Offer) – damit stimmen
// Preis und Verfuegbarkeit auch dann, wenn unten Empfehlungen stehen.
function suProduct(html, url) {
  let prod = null;
  for (const b of html.match(/<script[^>]*ld\+json[^>]*>[\s\S]*?<\/script>/g) || []) {
    const body = b.replace(/^[\s\S]*?>/, '').replace(/<\/script>$/, '');
    let d; try { d = JSON.parse(body); } catch (e) { continue; }
    const nodes = Array.isArray(d['@graph']) ? d['@graph'] : [d];
    const p = nodes.find((x) => x && x['@type'] === 'Product');
    if (p) { prod = p; break; }
  }
  if (!prod || !prod.name) throw new Error('Produktseite nicht lesbar');
  const off = Array.isArray(prod.offers) ? prod.offers[0] : prod.offers;
  const price = off ? parseFloat(off.price) : NaN;
  const id = String(prod.productID || prod['@id'] || url);
  return {
    id, pid: id, t: decodeEntities(prod.name),
    p: price > 0 ? price : null,
    a: off && /OutOfStock|SoldOut|Discontinued|BackOrder/i.test(String(off.availability || '')) ? 0 : 1,
    u: prod.url || url,
    i: Array.isArray(prod.image) ? prod.image[0] : (prod.image || ''),
    g: franchiseOf(prod.name + ' ' + (prod.category || '')),
  };
}

// ---- robots.txt beachten ----------------------------------------------------
// Welche Adressen ein Shop fuer automatische Abrufe freigibt, steht in seiner
// robots.txt. Bei Shopware entscheidet das, wie geblaettert werden darf:
// twomoons.ch erlaubt ausdruecklich "?p=", amazingtoys.ch verbietet jede Adresse
// mit Fragezeichen, gibt dafuer aber /widgets/cms/ frei - die Schnittstelle, die
// die Seite beim Blaettern selbst benutzt.
const robotsCache = new Map();
async function robotsRules(origin) {
  if (robotsCache.has(origin)) return robotsCache.get(origin);
  let rules = null;
  try {
    const res = await fetch(origin + '/robots.txt', { headers: { 'User-Agent': WATCH_UA } });
    if (res.ok) {
      rules = [];
      let forUs = false;
      for (const raw of (await res.text()).slice(0, 100000).split(/\r?\n/)) {
        const m = raw.replace(/#.*$/, '').trim().match(/^(user-agent|allow|disallow)\s*:\s*(.*)$/i);
        if (!m) continue;
        const k = m[1].toLowerCase(), v = m[2].trim();
        if (k === 'user-agent') forUs = v === '*';
        else if (forUs && v) rules.push([k === 'allow', v]);
      }
    }
  } catch (e) { /* keine robots.txt erreichbar -> keine Einschraenkung */ }
  robotsCache.set(origin, rules);
  return rules;
}
const robotsHit = (pat, path) => {
  const end = pat.endsWith('$');
  const body = (end ? pat.slice(0, -1) : pat).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  try { return new RegExp('^' + body + (end ? '$' : '')).test(path); } catch (e) { return false; }
};
// Es gilt die laengste zutreffende Regel; bei gleicher Laenge gewinnt Allow.
async function robotsAllows(url) {
  let u;
  try { u = new URL(url); } catch (e) { return true; }
  const rules = await robotsRules(u.origin);
  if (!rules || !rules.length) return true;
  const path = u.pathname + u.search;
  let best = null;
  for (const [allow, pat] of rules) {
    if (!robotsHit(pat, path)) continue;
    if (!best || pat.length > best[1] || (pat.length === best[1] && allow)) best = [allow, pat.length];
  }
  return best ? best[0] : true;
}

// Shopware 6 (z. B. twomoons.ch): jede Kachel traegt ihre Daten als JSON im
// Attribut data-product-information (id, Name, Marke, Preis); Link, Bild und der
// Kaufen-Knopf stehen daneben. 96 Artikel je Seite, dafuer sehr viel Markup.
const isShopware = (html) => html.includes('data-product-information="');
const isSwListing = (html) => /js-listing-wrapper|cms-listing-row/.test(html);
const isSwDetail = (html) => html.includes('product-detail-name');

function swItems(html) {
  const out = [];
  const parts = html.split('data-product-information="');
  for (let k = 1; k < parts.length; k++) {
    const c = parts[k], q = c.indexOf('"');
    if (q < 0) continue;
    let info = null;
    try { info = JSON.parse(decodeEntities(c.slice(0, q))); } catch (e) { continue; }
    if (!info || !info.id || !info.name) continue;
    const m = (re) => { const x = c.match(re); return x ? x[1] : ''; };
    const u = m(/<a\s[^>]*?href="([^"]+)"[^>]*?class="product-name/);
    if (!u) continue;
    const srcset = m(/data-srcset="([^"]+)"/) || m(/srcset="([^"]+)"/);
    const price = Number(info.price);
    const t = decodeEntities(String(info.name));
    out.push({
      id: String(info.id), t,
      p: price > 0 ? price : null,
      // Ausverkauftes blendet der Shop aus der Liste aus; der Kaufen-Knopf bleibt
      // trotzdem das ehrlichste Zeichen, falls er doch einmal etwas stehen laesst.
      a: /btn-buy/.test(c) ? 1 : 0,
      u, i: srcset.split(',')[0].trim().split(' ')[0],
      g: franchiseOf(t + ' ' + (info.brand || '') + ' ' + u),
      hay: t + ' ' + (info.brand || '') + ' ' + u,
    });
  }
  return out;
}

// Shopware liefert dieselbe Liste auch ueber /widgets/cms/... - dort passen bis zu
// 96 Artikel in einen Abruf, und es kommt nur das Raster statt der ganzen Seite.
// Die Adresse steht in der Seite, im Attribut data-listing-options.
const SW_LIMIT = 96;
function swDataUrl(html) {
  const m = html.match(/data-listing-options="([^"]*)"/);
  if (!m) return '';
  let o;
  try { o = JSON.parse(decodeEntities(m[1])); } catch (e) { return ''; }
  if (!o || !o.dataUrl) return '';
  const q = new URLSearchParams(o.params || {}).toString();
  return o.dataUrl + (q ? '?' + q : '');
}
function swWidgetUrl(base, data, n) {
  const u = new URL(data, base);
  u.searchParams.set('limit', String(SW_LIMIT));
  if (n > 1) u.searchParams.set('p', String(n));
  return u.toString();
}

function swPageUrl(base, n) {
  const u = new URL(base);
  if (n > 1) u.searchParams.set('p', String(n)); else u.searchParams.delete('p');
  return u.toString();
}

async function fetchShopware(src, plan) {
  let want = Array.isArray(plan) && plan.length ? plan : [1];
  // Beim ersten Lauf ist die Schnittstelle noch nicht bekannt; sie wird aus Seite 1
  // gelesen und ab dem naechsten Lauf verwendet. Innerhalb eines Laufs nicht wechseln,
  // sonst passten die Seitengrenzen nicht mehr zusammen.
  const data = (src.cat && (await robotsAllows(new URL(src.cat, src.url).toString()))) ? src.cat : '';
  if (!data && !(await robotsAllows(swPageUrl(src.url, 2)))) want = [1];   // Blaettern nicht erlaubt
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, firstCount = 0, perPage = 0, end = false, learned = src.cat || '';
  for (const p of want) {
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(data ? swWidgetUrl(src.url, data, p) : swPageUrl(src.url, p));
    pages++; bytes += b;
    if (!learned) learned = swDataUrl(html);
    const list = swItems(html);
    if (!list.length) {
      if (p === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      end = true; break;
    }
    let added = 0;
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id); added++;
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    if (p === 1) { firstCount = out.length; perPage = list.length; }
    // Hinter der letzten Seite gibt Shopware nicht etwa nichts zurueck, sondern
    // noch einmal dieselbe Liste. Kommt nichts Neues, ist Schluss.
    else if (!added) { end = true; break; }
    if (perPage && list.length < perPage) { end = true; break; }   // letzte Seite war nicht voll
  }
  if (want.length === 1 && !end) end = true;   // nur Seite 1 erlaubt: nicht weiterwandern
  return { list: out, pages, bytes, firstCount, end, cat: learned };
}

// Produktseite: Name in der H1 (ohne die Marken-Zeile darueber), Preis als
// Mikrodaten-Angabe. Die id spielt hier keine Rolle, beobachtete Produkte
// bekommen ohnehin einen festen Schluessel.
function swProduct(html, url) {
  const h1 = (html.match(/<h1[^>]*class="[^"]*product-detail-name[^"]*"[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || '';
  // In der H1 steht die Marke als eigene Zeile ueber dem Namen – sie gehoert nicht in
  // den Titel, hilft aber beim Zuordnen des Franchise.
  const brand = stripTags((h1.match(/<span class="subheadings">([\s\S]*?)<\/span>/) || [])[1]);
  const t = stripTags(h1.replace(/<span class="subheadings">[\s\S]*?<\/span>/g, '')
    .replace(/<span class="product-va[\s\S]*$/, ''));
  if (!t) throw new Error('Produktseite nicht lesbar');
  const price = parseFloat((html.match(/itemprop="price"[^>]*content="([^"]+)"/) || [])[1]);
  const u = (html.match(/rel="canonical" href="([^"]+)"/) || [])[1] || url;
  // Produktbild, nicht das Shop-Logo
  const gal = (html.match(/<img[^>]*js-magnifier-image[^>]*>/) || [''])[0];
  const img = (gal.match(/\ssrc="([^"]+)"/) ||
    html.match(/src="(https?:\/\/[^"]*\/(?:thumbnail|media)\/(?:(?!logo)[^"])+\.(?:jpg|jpeg|png|webp)[^"]*)"/) || [])[1] || '';
  return {
    id: u, pid: u, t,
    p: price > 0 ? price : null,
    a: /btn-buy/.test(html) ? 1 : 0,
    u, i: img,
    g: franchiseOf(t + ' ' + brand + ' ' + u),
  };
}

// PrestaShop 1.6 und seine Abkoemmlinge (thirty bees), z. B. themanashop.ch und
// spielezar.ch. Gemeinsam ist beiden nur das Geruest: Kacheln "ajax_block_product"
// mit data-id-product innerhalb der Liste <div class="product_list">. Name, Preis,
// Lagerstand und das Blaettern macht jedes Theme anders, darum wird beides versucht.
// Nach Datum sortieren verbietet die robots.txt beider Shops (orderby, orderway, n),
// darum liest der Monitor hier mit dem wandernden Fenster.
// 1.6 und thirty bees nennen die Kachel "ajax_block_product", 1.7 "js-product-miniature".
const isPresta = (html) => (html.includes('ajax_block_product') || html.includes('js-product-miniature')) && html.includes('data-id-product=');
const isPsListing = (html) => html.includes('class="product_list') || html.includes('id="js-product-list"');
const isPsDetail = (html) => html.includes('itemprop="availability"') && !isPsListing(html);
const psPrice = textPrice;
const psStock = (s) => (/InStock|PreOrder|BackOrder|LimitedAvailability/i.test(s) ? 1 : 0);

function psItems(html) {
  // 1.6 und thirty bees listen in <div class="product_list">, 1.7 in <div id="js-product-list">.
  let start = html.indexOf('class="product_list');
  if (start < 0) start = html.indexOf('id="js-product-list"');
  if (start < 0) return [];     // Startseite o. \u00c4.: lose Kacheln ohne Liste ignorieren
  const body = html.slice(start);
  const marker = body.includes('js-product-miniature') ? 'js-product-miniature' : 'ajax_block_product';
  const out = [];
  for (const chunk of body.split(marker).slice(1)) {
    // Kachelgrenze. Ohne sie erbte die letzte Kachel den ganzen Rest der Seite \u2013
    // mitsamt den Preisen aus Karussells weiter unten.
    const cut = chunk.indexOf('</form>');
    const c = chunk.slice(0, cut > 200 ? cut : 8000);
    const m = (re) => { const x = c.match(re); return x ? x[1] : ''; };
    // Erst die Themes mit eigener Link-Klasse, sonst der Titel-Link, sonst der erste echte Link.
    const link = (c.match(/<a[^>]*class="(?:product_img_link|product-name|no-underline)"[^>]*>/)
      || c.match(/product-title[^>]*>\s*<a[^>]*>/)
      || c.match(/<a[^>]+href="https?:\/\/[^"]+"[^>]*>/) || [''])[0];
    const u = (link.match(/href="([^"]+)"/) || [])[1] || '';
    // Der sichtbare Linktext ist in manchen Themes abgeschnitten ("Sleeved..."),
    // das title-Attribut traegt den vollen Namen.
    const t = decodeEntities((link.match(/title="([^"]*)"/) || [])[1]
      || stripTags(m(/<h[1-6][^>]*product-title[^>]*>([\s\S]*?)<\/h[1-6]>/) || m(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/)));
    if (!u || !t) continue;
    const av = m(/itemprop="availability"[^>]*(?:href|content)="([^"]*)"/);
    out.push({
      id: m(/data-id-product="(\d+)"/) || (u.match(/\/(\d+)-/) || [])[1] || u,
      t,
      p: psPrice(m(/itemprop="price"[^>]*content="([^"]+)"/)
        || m(/<span[^>]*itemprop="price"[^>]*>([^<]*)</)
        || m(/class="price_default"[^>]*>([^<]*)</)
        || m(/<span[^>]*class="[^"]*\bprice\b[^"]*"[^>]*>([^<]*)</)),
      // Mikrodaten, wo vorhanden; sonst der Knopf- oder Lagertext.
      // "Vorausbestellen" zaehlt als verfuegbar, denn kaufen laesst es sich.
      a: av ? psStock(av) : (/product-unavailable|Out-of-Stock|Nicht auf Lager/i.test(c) ? 0 : 1),
      u, i: m(/<img[^>]*\ssrc\s*=\s*"([^"]+)"/),
      g: franchiseOf(t + ' ' + u),
      hay: t + ' ' + u,
    });
  }
  return out;
}

// Geblaettert wird je nach Fassung mit ?p=2 (1.6), ?page=2 (1.7) oder ?offset=30
// (thirty bees). Welches gilt, verraet die erste Seite mit ihren eigenen
// Blaetter-Links.
const psMode = (html) => (/[?&]offset=\d/.test(html) ? 'offset' : /[?&]page=\d/.test(html) ? 'page' : 'p');
function psPageUrl(base, n, mode, per) {
  const u = new URL(base);
  u.searchParams.delete('p'); u.searchParams.delete('page'); u.searchParams.delete('offset');
  if (n > 1) {
    if (mode === 'offset') u.searchParams.set('offset', String((n - 1) * per));
    else u.searchParams.set(mode === 'page' ? 'page' : 'p', String(n));
  }
  return u.toString();
}

async function fetchPresta(src, plan) {
  const want = Array.isArray(plan) && plan.length ? plan : [1];
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, firstCount = 0, perPage = 0, mode = 'p', end = false;
  for (const p of want) {
    if (p > 1 && !perPage) break;        // ohne Seite 1 ist nicht bekannt, wie geblaettert wird
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(psPageUrl(src.url, p, mode, perPage));
    pages++; bytes += b;
    const list = psItems(html);
    if (!list.length) {
      if (p === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      end = true; break;
    }
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    if (p === 1) { firstCount = out.length; perPage = list.length; mode = psMode(html); }
    else if (list.length < perPage) { end = true; break; }   // letzte Seite war nicht voll
  }
  return { list: out, pages, bytes, firstCount, end };
}

// Produktseite: die Mikrodaten sind dem sichtbaren Markup vorzuziehen \u2013 unter dem
// Produkt haengt ein Zubehoer-Karussell mit eigenen Preisen und eigenem Lagerstand.
function psProduct(html, url) {
  // Erst die Ueberschrift: das itemprop="name" ganz oben gehoert bei manchen
  // Themes dem Laden, nicht dem Artikel (toytans nennt sich dort selbst).
  const t = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || '')
    || (html.match(/itemprop="name" content="([^"]*)"/) || [])[1] || '');
  if (!t) throw new Error('Produktseite nicht lesbar');
  const price = psPrice((html.match(/<meta itemprop="price" content="([^"]+)"/) || [])[1]
    || (html.match(/<span[^>]*itemprop="price"[^>]*>([^<]*)</) || [])[1]);
  const u = (html.match(/rel="canonical" href="([^"]+)"/) || [])[1]
    || (html.match(/property="og:url" content="([^"]+)"/) || [])[1] || url;
  // Bild-Tag erst suchen, dann das src darin: die Attribute stehen in wechselnder
  // Reihenfolge und ueber mehrere Zeilen verteilt.
  const img = ((html.match(/<img[^>]*itemprop="image"[^>]*>/) || [''])[0].match(/\ssrc="([^"]+)"/) || [])[1]
    || (html.match(/property="og:image" content="([^"]+)"/) || [])[1] || '';
  return {
    id: u, pid: u, t,
    p: price > 0 ? price : null,
    a: psStock((html.match(/itemprop="availability"[^>]*(?:href|content)="([^"]*)"/) || [])[1] || ''),
    u, i: img,
    g: franchiseOf(t + ' ' + u),
  };
}

// Shops, die ihre Liste als JSON-LD mitliefern (schema.org, CollectionPage mit
// ItemList), z. B. brack.ch. Das ist die sauberste Quelle ueberhaupt: Name, Preis,
// Verfuegbarkeit und Bild stehen fertig da, es muss kein Markup geraten werden.
// Geblaettert wird mit ?page=N. Weil die robots.txt dort das Sortieren verbietet
// (sortProducts), steht die Liste in Ladensortierung - darum das wandernde Fenster.
function ldNodes(html) {
  const out = [];
  for (const m of html.matchAll(/<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/g)) {
    let j;
    try { j = JSON.parse(m[1]); } catch (e) { continue; }
    for (const n of Array.isArray(j) ? j : [j]) if (n && typeof n === 'object') out.push(n);
  }
  return out;
}
function ldListOf(html) {
  for (const n of ldNodes(html)) {
    const l = (n.mainEntity && n.mainEntity.itemListElement) || (n['@type'] === 'ItemList' && n.itemListElement);
    if (Array.isArray(l) && l.length) return l;
  }
  return null;
}
// Produktseite: ein Product, oder eine ProductGroup, deren Varianten die Preise tragen.
function ldProductOf(html, url) {
  const want = (() => { try { return new URL(url).pathname; } catch (e) { return url; } })();
  for (const n of ldNodes(html)) {
    const vs = Array.isArray(n.hasVariant) ? n.hasVariant : n['@type'] === 'Product' ? [n] : [];
    if (!vs.length) continue;
    const hit = vs.find((v) => v && v.url && (v.url === want || String(v.url).endsWith(want)));
    const v = hit || vs[0];
    if (v && v.name) return Object.assign({}, v, { name: v.name || n.name });
  }
  return null;
}
const isJsonLdList = (html) => !!ldListOf(html);
const isJsonLdProduct = (html) => !ldListOf(html) && !!ldProductOf(html, '');

const ldStock = (s) => (/InStock|PreOrder|BackOrder|LimitedAvailability/i.test(String(s || '')) ? 1 : 0);
function ldOne(p, base) {
  const off = (Array.isArray(p.offers) ? p.offers[0] : p.offers) || {};
  const u = new URL(p.url, base).toString();
  const t = decodeEntities(String(p.name || ''));
  const price = Number(off.price);
  return {
    // Eine eigene Produktnummer liefert das JSON-LD nicht immer; die Nummer am
    // Ende der Adresse ist stabil, sonst nimmt die Adresse selbst ihren Platz ein.
    id: String(p.sku || p.productID || (u.match(/-(\d{5,})(?:[/?#]|$)/) || [])[1] || u),
    t,
    p: price > 0 ? price : null,
    a: ldStock(off.availability),
    u,
    i: (Array.isArray(p.image) ? p.image[0] : p.image) || '',
    g: franchiseOf(t + ' ' + (typeof p.brand === 'string' ? p.brand : (p.brand && p.brand.name) || '') + ' ' + u),
    hay: t + ' ' + (p.description || '') + ' ' + u,
  };
}

function ldItems(html, base) {
  const out = [];
  for (const e of ldListOf(html) || []) {
    const p = (e && e.item) || e;
    if (p && p.name && p.url) out.push(ldOne(p, base));
  }
  return out;
}

function ldPageUrl(base, n) {
  const u = new URL(base);
  if (n > 1) u.searchParams.set('page', String(n)); else u.searchParams.delete('page');
  return u.toString();
}

async function fetchJsonLd(src, plan) {
  const want = Array.isArray(plan) && plan.length ? plan : [1];
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, firstCount = 0, perPage = 0, end = false;
  for (const p of want) {
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(ldPageUrl(src.url, p));
    pages++; bytes += b;
    const list = ldItems(html, src.url);
    if (!list.length) {
      if (p === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      end = true; break;
    }
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    if (p === 1) { firstCount = out.length; perPage = list.length; }
    else if (list.length < perPage) { end = true; break; }   // letzte Seite war nicht voll
  }
  return { list: out, pages, bytes, firstCount, end };
}

function ldProduct(html, url) {
  const p = ldProductOf(html, url);
  if (!p) throw new Error('Produktseite nicht lesbar');
  const x = ldOne(p, url);
  delete x.hay;
  return Object.assign(x, { id: x.u, pid: x.u });
}

// ePages 6, die klassische Fassung (z. B. fabitasia-cards.ch). Nicht zu verwechseln
// mit ePages Now (calandamagic.ch), das eine JSON-Schnittstelle hat - hier gibt es
// nur HTML: Kacheln mit data-productGUID, Preis und Lagerstand als Mikrodaten.
// Wichtig ist die Adresse: an der blanken Domain laesst der Shop jeden Parameter
// fallen, gearbeitet wird mit dem Einstieg /epages/<nummer>.sf/<sprache>/.
const E6_PER_PAGE = 36;
const isEpages6 = (html) => html.includes('data-productGUID') && /\/epages\/\d+\.sf\//.test(html);
const isE6Detail = (html) => html.includes('itemprop="availability"') && !html.includes('class="CategoryProducts"');
const e6Base = (html, url) => (html.match(/https?:\/\/[^"'\s]+\/epages\/\d+\.sf\/[A-Za-z_]+\//) || [url])[0];

function e6Items(html, base) {
  const out = [];
  // Die Kacheln liegen zwischen 1400 und 2900 Zeichen auseinander; die letzte wuerde
  // ohne Grenze den ganzen Seitenfuss erben.
  for (const chunk of html.split('data-productGUID=').slice(1)) {
    const c = chunk.slice(0, 3000);
    const id = (c.match(/"id":\s*"([^"]+)"/) || [])[1];
    const a = c.match(/<h3[^>]*>\s*<a\s+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!id || !a) continue;
    const t = decodeEntities(stripTags(a[2]));
    if (!t) continue;
    const u = new URL(decodeEntities(a[1]), base).toString();
    const img = (c.match(/<img[^>]*class="[^"]*ProductSmallImage[^"]*"[^>]*\ssrc="([^"]+)"/) || [])[1] || '';
    out.push({
      id, t,
      p: Number((c.match(/itemprop=['"]price['"][^>]*content=['"]([^'"]+)/) || [])[1]) || null,
      // Das Lager-Symbol steht nur bei kaufbarer Ware ("Auf Lager" oder "Begrenzter
      // Lagerbestand"). Fehlt es, ist der Artikel aus - an den Kacheln selbst steht
      // das nirgends, nachgeprueft an den Produktseiten.
      a: /Product(On|Warn)StockIcon/.test(c) ? 1 : 0,
      u, i: img ? new URL(img, base).toString() : '',
      g: franchiseOf(t + ' ' + u),
      hay: t + ' ' + u,
    });
  }
  return out;
}

const e6PageUrl = (base, n) => {
  const u = new URL(base);
  u.searchParams.set('PageSize', String(E6_PER_PAGE));
  if (n > 1) u.searchParams.set('Page', String(n)); else u.searchParams.delete('Page');
  return u.toString();
};

async function fetchEpages6(src, max) {
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, truncated = false;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(e6PageUrl(src.url, page));
    pages++; bytes += b;
    const list = e6Items(html, src.url);
    if (!list.length) {
      if (page === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      break;
    }
    let added = 0;
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id); added++;
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    // Die Startseite des Shops blaettert gar nicht und liefert immer dieselbe Liste.
    // Kommt nichts Neues mehr, ist Schluss - sonst holten wir jede Runde dasselbe.
    if (!added) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

function e6Product(html, url) {
  const t = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || ''));
  if (!t) throw new Error('Produktseite nicht lesbar');
  const u = (html.match(/rel="canonical" href="([^"]+)"/) || [])[1] || url;
  const avail = (html.match(/itemprop=['"]availability['"][^>]*content=['"]([^'"]+)/) || [])[1] || '';
  const img = (html.match(/property="og:image" content="([^"]+)"/) || [])[1]
    || (html.match(/<img[^>]*itemprop="image"[^>]*\ssrc="([^"]+)"/) || [])[1] || '';
  return {
    id: u, pid: u, t,
    p: Number((html.match(/itemprop=['"]price['"][^>]*content=['"]([^'"]+)/) || [])[1]) || null,
    a: /InStock|PreOrder|BackOrder|LimitedAvailability/i.test(avail) ? 1 : 0,
    u, i: img ? new URL(img, url).toString() : '',
    g: franchiseOf(t + ' ' + u),
  };
}

// manor.ch: eine Next.js-Seite, die ihre Produkte fertig mitliefert - im Zustand
// __NEXT_DATA__ unter initialApolloState, je Artikel ein Eintrag "IndexedProduct".
// Name, Preis, Lagerstand, Bild und Link stehen dort sauber beieinander.
// 48 Artikel je Seite, geblaettert wird mit ?page=N (Seite 1 ohne den Parameter).
const MANOR_PER_PAGE = 48;
function manorState(html) {
  const m = html.match(/__NEXT_DATA__[^>]*>([\s\S]*?)<\/script>/);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch (e) { return null; }
}
function manorProducts(html) {
  const j = manorState(html);
  const ap = j && j.props && j.props.pageProps && j.props.pageProps.initialApolloState;
  if (!ap) return null;
  const out = Object.keys(ap).filter((k) => k.startsWith('IndexedProduct:')).map((k) => ap[k]);
  return out.length ? out : null;
}
const isManor = (html) => !!manorProducts(html);

function manorItems(html) {
  const out = [];
  for (const p of manorProducts(html) || []) {
    const first = (p.titles && p.titles.first) || p.brandName || '';
    const base = p.name || (p.titles && p.titles.third) || '';
    if (!base || !p.link) continue;
    // Der Name allein heisst manchmal nur "Sammelkartenbox"; die Marke steht daneben.
    const t = first && !base.toLowerCase().includes(first.toLowerCase()) ? first + ' \u00b7 ' + base : base;
    const st = (p.stock && p.stock.status) || '';
    out.push({
      id: String(p.code || p.id),
      t,
      p: p.priceValue && p.priceValue.amount > 0 ? p.priceValue.amount : null,
      a: /OUT_OF_STOCK|SOLD_OUT|NOT_AVAILABLE/i.test(st) ? 0 : 1,
      u: p.link,
      i: (p.imageUrls && (p.imageUrls.desktop || p.imageUrls.mobile)) || '',
      g: franchiseOf(t + ' ' + (p.brandName || '') + ' ' + p.link),
      hay: t + ' ' + (p.brandName || '') + ' ' + p.link,
    });
  }
  return out;
}

const manorPageUrl = (base, n) => {
  const u = new URL(base);
  if (n > 1) u.searchParams.set('page', String(n)); else u.searchParams.delete('page');
  return u.toString();
};

async function fetchManor(src, max) {
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, truncated = false;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    if (pages) await sleep(HOST_PAUSE);
    const { html, bytes: b } = await getHtml(manorPageUrl(src.url, page));
    pages++; bytes += b;
    const list = manorItems(html);
    if (!list.length) {
      if (page === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      break;
    }
    let added = 0;
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id); added++;
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    if (!added || list.length < MANOR_PER_PAGE) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

// Produktseite: derselbe Zustand, nur mit genau einem Eintrag.
function manorProduct(html, url) {
  const one = manorItems(html)[0];
  if (!one) throw new Error('Produktseite nicht lesbar');
  delete one.hay;
  return Object.assign(one, { id: one.u, pid: one.u });
}

// softridge.ch: die Seite selbst ist leer, die Liste holt sich das Javascript von
// /api/shop/products. Die vollstaendige Adresse dieser Schnittstelle steht als
// verstecktes Feld "productsApiUrl" in der Seite - die merkt sich der Monitor beim
// Anlegen und fragt danach nur noch die Schnittstelle. Sie sortiert von Haus aus
// nach Erscheinungsdatum absteigend, also stehen Neuheiten vorn. 20 je Seite.
const srApi = (html) => decodeEntities((html.match(/id="productsApiUrl"[^>]*\svalue="([^"]+)"/)
  || html.match(/\svalue="([^"]*\/api\/shop\/products[^"]*)"/) || [])[1] || '');
const isSoftridge = (html) => !!srApi(html);

const srPageUrl = (src, n) => new URL(src.cat + '&page=' + n, src.url).toString();

function srItems(j, base) {
  const out = [];
  for (const p of (j && j.products) || []) {
    const t = decodeEntities(String(p.fullTitle || ''));
    if (!t || !p.linkUrl) continue;
    const u = new URL(p.linkUrl, base).toString();
    out.push({
      id: String(p.navisionId || p.id),
      t,
      p: p.salesPrice > 0 ? p.salesPrice : null,
      // Grau heisst ausverkauft; blau und gelb sind Vorbestellungen mit Liefertermin,
      // gruen ist sofort da. An den Produktseiten gegengeprueft.
      a: p.statusColor === 'Gray' ? 0 : 1,
      u,
      i: p.coverUrl ? new URL(p.coverUrl, base).toString() : '',
      g: franchiseOf(t + ' ' + (p.consoleName || '') + ' ' + u),
      hay: t + ' ' + (p.consoleName || '') + ' ' + (p.publisherAndGenreText || '') + ' ' + u,
    });
  }
  return out;
}

async function fetchSoftridge(src, max) {
  const out = [], seen = new Set();
  let pages = 0, bytes = 0, truncated = false;
  for (let page = 1; page <= (max || MAX_PAGES); page++) {
    if (pages) await sleep(HOST_PAUSE);
    const { data, bytes: b } = await getJson(srPageUrl(src, page));
    pages++; bytes += b;
    const list = srItems(data, src.url);
    if (!list.length) {
      if (page === 1) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
      break;
    }
    for (const it of list) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      if (passes(src, it.hay)) { delete it.hay; out.push(it); }
    }
    if (!data.hasMore) break;
    if (page === (max || MAX_PAGES)) truncated = true;
  }
  return { list: out, pages, bytes, truncated };
}

// Wix-Shops (z. B. framicards.ch): die Seite ist eine React-App, liefert ihre Liste
// aber im Script "wix-warmup-data" gleich mit. Die Besonderheit: ?page=N ist dort
// keine einzelne Seite, sondern eine Menge - page=3 bringt die ersten dreimal 48
// Artikel auf einen Schlag. Ein Abruf je Lauf genuegt also.
const WIX_PER_PAGE = 48;
function wixList(html) {
  const m = html.match(/<script[^>]*id="wix-warmup-data"[^>]*>([\s\S]*?)<\/script>/);
  if (!m) return null;
  let j;
  try { j = JSON.parse(m[1]); } catch (e) { return null; }
  const find = (o, d) => {
    if (d > 8 || !o || typeof o !== 'object') return null;
    if (o.productsWithMetaData && Array.isArray(o.productsWithMetaData.list)) return o.productsWithMetaData;
    for (const k of Object.keys(o)) { const r = find(o[k], d + 1); if (r) return r; }
    return null;
  };
  return find(j, 0);
}
const isWix = (html) => !!wixList(html);
// Name der Kategorie steht im selben Zustand.
function wixCategory(html) {
  const m = html.match(/"category":\{"id":"[^"]*","name":"((?:[^"\\]|\\.)*)"/);
  try { return m ? JSON.parse('"' + m[1] + '"') : ''; } catch (e) { return ''; }
}

function wixItems(pm, base, cat) {
  const out = [];
  for (const p of (pm && pm.list) || []) {
    if (!p || !p.name || !p.urlPart) continue;
    const u = new URL('/product-page/' + p.urlPart, base).toString();
    const t = decodeEntities(String(p.name));
    const img = (Array.isArray(p.media) && p.media[0]) || {};
    out.push({
      id: String(p.id),
      t,
      p: p.price > 0 ? p.price : null,
      a: p.isInStock ? 1 : 0,
      u,
      i: img.fullUrl || img.url || '',
      // Die Artikelnamen bei Wix nennen das Franchise oft nicht ("30th Celebration
      // Ditto Premium Collection"); dann entscheidet der Name der Kategorie.
      g: franchiseOf(t + ' ' + u) || franchiseOf(cat || ''),
      // Die Kategorie gehoert auch in den Heuhaufen, sonst wirft ein Franchise-Filter
      // genau die Artikel weg, die der Chip daneben als Pokémon ausweist.
      hay: t + ' ' + (p.sku || '') + ' ' + u + ' ' + (cat || ''),
    });
  }
  return out;
}

const wixPageUrl = (base, n) => {
  const u = new URL(base);
  if (n > 1) u.searchParams.set('page', String(n)); else u.searchParams.delete('page');
  return u.toString();
};

async function fetchWix(src, max) {
  // max ist hier keine Seitenzahl zum Durchblaettern, sondern wie weit die eine
  // Liste reichen soll. Normal reicht die erste Ladung (die Neusten stehen vorn),
  // ab und zu liest ein Lauf tiefer.
  const n = Math.max(1, Math.min(max || 1, 4));
  const { html, bytes } = await getHtml(wixPageUrl(src.url, n));
  const pm = wixList(html);
  if (!pm) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
  const out = [];
  for (const it of wixItems(pm, src.url, wixCategory(html))) {
    if (passes(src, it.hay)) { delete it.hay; out.push(it); }
  }
  // pages meldet die Tiefe, nicht die Zahl der Abrufe: nur so merkt der Vergleich,
  // dass dieser Lauf weiter gelesen hat, und schluckt die Nachzuegler still.
  return { list: out, pages: n, bytes, truncated: (pm.totalCount || 0) > (pm.list || []).length };
}

// friends-collective.site (die Bilder liegen auf factory.nosama.store, daher der
// Name). Next.js mit App Router: die Produkte stehen nicht im Markup, sondern in
// den Datenpaketen self.__next_f.push([1,"..."]). Dort liegt allerdings der ganze
// Katalog, auch wenn die Seite nur eine Welt zeigt. Welche Artikel gemeint sind,
// verraten die Produktlinks im gerenderten HTML - so bleibt der Filter des Shops
// (?world=one-piece) erhalten, ohne ihn nachbauen zu muessen.
function nosamaFlight(html) {
  let all = '';
  for (const m of html.matchAll(/self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)/g)) {
    try { all += JSON.parse(m[1]); } catch (e) { /* angebrochenes Paket */ }
  }
  return all;
}
// Die Objekte stehen mitten im Datenstrom, nicht als eigenes JSON. Darum von
// {"factoryProductId" aus die Klammern zaehlen, bis das Objekt zu ist.
function nosamaProducts(html) {
  const all = nosamaFlight(html);
  const out = new Map();
  let i = -1;
  while ((i = all.indexOf('{"factoryProductId"', i + 1)) >= 0) {
    const stop = Math.min(all.length, i + 20000);
    let depth = 0, j = i, inStr = false, esc = false;
    for (; j < stop; j++) {
      const c = all[j];
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (!depth) { j++; break; } }
    }
    if (depth) continue;
    try { const o = JSON.parse(all.slice(i, j)); if (o.factoryProductId) out.set(o.factoryProductId, o); } catch (e) { /* weiter */ }
  }
  return out;
}
// Im Quelltext steht das Feld escaped ({\"factoryProductId\"), darum ohne
// Anfuehrungszeichen suchen. Ob die Seite auch Produkte zeigt, ist eine zweite
// Frage - die beantwortet die Erkennung mit einer eigenen Meldung.
const isNosama = (html) => html.includes('factoryProductId') && html.includes('__next_f');
const hasNosamaLinks = (html) => /href="\/[a-z]{2}\/shop\/products\/[0-9a-f-]{36}"/.test(html);

function nosamaItems(html, base) {
  const data = nosamaProducts(html);
  const out = [], seen = new Set();
  // Reihenfolge und Auswahl wie auf der Seite.
  for (const m of html.matchAll(/href="(\/[a-z]{2}\/shop\/products\/([0-9a-f-]{36}))"/g)) {
    const id = m[2];
    if (seen.has(id)) continue;
    seen.add(id);
    const p = data.get(id);
    if (!p || !p.title) continue;
    const t = decodeEntities(String(p.title));
    const u = new URL(m[1], base).toString();
    const brand = String(p.brand || '').replace(/_/g, ' ');
    out.push({
      id,
      t,
      // Preise stehen in Rappen.
      p: p.priceMinor > 0 ? p.priceMinor / 100 : null,
      a: p.buyable && (p.availableQuantity == null || p.availableQuantity > 0) ? 1 : 0,
      u,
      i: p.imageUrl || (Array.isArray(p.imageUrls) ? p.imageUrls[0] : '') || '',
      g: franchiseOf(t + ' ' + brand + ' ' + u),
      hay: t + ' ' + brand + ' ' + (p.setCode || '') + ' ' + u,
    });
  }
  return out;
}

async function fetchNosama(src) {
  const { html, bytes } = await getHtml(src.url);
  const list = nosamaItems(html, src.url);
  if (!list.length) throw new Error(new URL(src.url).host + ': keine Produktliste gefunden');
  const out = [];
  for (const it of list) if (passes(src, it.hay)) { delete it.hay; out.push(it); }
  return { list: out, pages: 1, bytes };
}

const fetchSource = (src, max) => (src.item ? fetchItem(src).then((r) => { r.list.forEach((x) => { x.id = 'x'; }); return r; }) : src.type === 'wog' ? fetchWog(src) : src.type === 'woocommerce' ? fetchWoo(src, max) : src.type === 'epages' ? fetchEpages(src, max) : src.type === 'cscart' ? fetchCs(src, max) : src.type === 'sumup' ? fetchSumup(src, max) : src.type === 'shopware' ? fetchShopware(src, max)
  : src.type === 'prestashop' ? fetchPresta(src, max)
  : src.type === 'jsonld' ? fetchJsonLd(src, max)
  : src.type === 'epages6' ? fetchEpages6(src, max)
  : src.type === 'manor' ? fetchManor(src, max)
  : src.type === 'softridge' ? fetchSoftridge(src, max)
  : src.type === 'wix' ? fetchWix(src, max)
  : src.type === 'nosama' ? fetchNosama(src) : fetchShopify(src, max));
const srcKey = (s) => (s.item ? 'item:' + new URL(s.url).origin + '|' + (s.item.handle || s.item.slug || s.item.pid) + '|' + (s.item.vid || '') : s.type === 'wog' ? 'wog' : s.type === 'woocommerce' ? wooApi(s) + '#' + (s.cat || '') : s.type === 'epages' ? epagesApi(s) + '#' + (s.cat || '') : s.type === 'cscart' ? csClean(s.url) : s.type === 'sumup' ? suPageUrl(s.url, 1) : s.type === 'shopware' ? swPageUrl(s.url, 1)
  : s.type === 'prestashop' ? psPageUrl(s.url, 1, 'p', 0)
  : s.type === 'jsonld' ? ldPageUrl(s.url, 1)
  : s.type === 'epages6' ? e6PageUrl(s.url, 1)
  : s.type === 'manor' ? manorPageUrl(s.url, 1)
  : s.type === 'softridge' ? srPageUrl(s, 1)
  : s.type === 'wix' ? wixPageUrl(s.url, 1)
  : s.type === 'nosama' ? s.url : shopifyApi(s));


// Shop-Typ erkennen (wog.ch, Shopify, WooCommerce) und einen lesbaren Namen bilden.
async function detectSource(url) {
  let u;
  try { u = new URL(url.includes('://') ? url : 'https://' + url); } catch (e) { throw new Error('keine gültige URL'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('keine gültige URL');
  const host = u.hostname.replace(/^www\./, '');
  const shop = host.replace(/\.(ch|com|de|eu|net|shop|store|site|li|at|io|online)$/, '');
  if (/(^|\.)wog\.ch$/.test(host)) return { type: 'wog', url: DEFAULT_SOURCES[0].url, name: 'World of Games' };

  const clean = u.origin + u.pathname.replace(/\/+$/, '');
  const probe = { url: clean };
  // Ein Shop ist höchstens eines von beiden, also beide Schnittstellen gleichzeitig
  // anklopfen statt zwei Rundreisen nacheinander abzuwarten. Fehler sind hier normal
  // (wer kein Shopify ist, antwortet mit 404) und bedeuten nur: nächste Möglichkeit.
  const miss = Symbol('kein Treffer');
  const [sh, wo] = await Promise.all([
    getJson(shopifyApi(probe) + '?limit=1').then((r) => r.data, () => miss),
    getJson(wooApi(probe) + '/products?per_page=1').then((r) => r.data, () => miss),
  ]);
  if (sh !== miss && sh && Array.isArray(sh.products)) {
    const m = u.pathname.match(/\/collections\/([^/]+)/);
    return { type: 'shopify', url: clean, name: m && m[1] !== 'all' ? shop + ' · ' + m[1] : shop };
  }
  if (wo !== miss && Array.isArray(wo)) {
    try {
      const cat = await wooCategoryId(probe);
      return { type: 'woocommerce', url: clean, cat: cat && cat.id, name: cat ? shop + ' · ' + cat.name : shop };
    } catch (e) {
      if (/Kategorie/.test(e.message)) throw e;   // sagt dem Benutzer, was zu tun ist
    }
  }
  // Shops ohne offene Schnittstelle: die Seite einmal holen und daraus erkennen.
  // Mit Query – bei manchen Shops steckt die Liste genau darin.
  const withQuery = clean + (u.search || '');
  let html = null, blocked = '', down = '';
  try { ({ html } = await getHtml(withQuery)); }
  catch (e) { if (BLOCKED.test(e.message)) blocked = e.message; else down = e.message; }
  if (html) {
    if (isEpages6(html)) {
      // Die Adresse auf den Shop-Einstieg bringen; sonst wird jeder Parameter ignoriert.
      const b = e6Base(html, clean);
      const keep = /[?&]ObjectPath=/.test(withQuery) ? new URL(withQuery).search : '';
      // Auf einer Kategorieseite steht im Titel die Kategorie, nicht der Laden -
      // der Shopname taugt von dort nur, wenn es keine Ueberschrift gibt.
      const site = decodeEntities(((html.match(/<title>([\s\S]*?)<\/title>/) || [])[1] || '').split(/[-|\u2013]/)[0].trim()) || shop;
      const h1 = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || ''));
      return { type: 'epages6', url: b + keep, name: h1 ? shop + ' \u00b7 ' + h1 : site, shopName: shop, html };
    }
    const cat = epagesFromHtml(u.pathname, html);   // wirft bei unbekannter Kategorie
    if (cat) {
      const name = cat.shop || shop;
      return { type: 'epages', url: clean, cat: cat.id, name: cat.id ? name + ' · ' + cat.name : name };
    }
    const cs = csFromHtml(html);
    if (cs) {
      const name = cs.shop || shop;
      // html/shopName nur fuer probeLink; gespeichert werden nur id/name/url/type/fr/cat
      return { type: 'cscart', url: withQuery, name: cs.name ? name + ' · ' + cs.name : name, shopName: name, html };
    }
    if (isShopware(html)) {
      const site = decodeEntities((html.match(/property="og:site_name" content="([^"]*)"/) || [])[1] || '')
        || stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1]) || shop;
      // Die Listen-Schnittstelle gleich mitnehmen, dann muss sie nicht erst
      // im ersten Lauf gelernt werden.
      return { type: 'shopware', url: withQuery, cat: swDataUrl(html) || undefined, name: site, shopName: site, html };
    }
    if (isPresta(html)) {
      // Den Zaehler aus der Ueberschrift werfen ("Es gibt 187 Artikel."),
      // der hat im Namen der Quelle nichts verloren.
      const h1 = decodeEntities(stripTags(((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || '')
        .replace(/<span[^>]*class="[^"]*counter[^"]*"[\s\S]*?<\/span>/g, '')));
      // Auf einer Produktseite ist die h1 der Produktname; die taugt nicht als Quellenname.
      const label = isPsListing(html) && h1 ? shop + ' \u00b7 ' + h1 : shop;
      return { type: 'prestashop', url: clean, name: label, shopName: shop, html };
    }
    if (isSumUpList(html) || isSumUpProduct(html)) {
      const site = decodeEntities((html.match(/og:site_name" content="([^"]*)"/) || [])[1] || '') || shop;
      // Query behalten: darin steckt die Sortierung „Neuste zuerst“
      return { type: 'sumup', url: withQuery, name: site, shopName: site, html };
    }
    if (isNosama(html)) {
      // Ohne Welt zeigt der Laden nur eine Startseite ohne Produkte.
      if (!hasNosamaLinks(html)) {
        throw new Error(host + ': diese Seite zeigt keine Produkte \u2013 bitte eine Welt w\u00e4hlen, z. B. ?world=all oder ?world=pokemon');
      }
      // Query behalten: darin steckt die Welt (?world=one-piece). Die taugt auch
      // als Name; die Ueberschrift ist dort je nach Welt ein Werbespruch.
      const world = (withQuery.match(/[?&]world=([a-z0-9-]+)/i) || [])[1] || '';
      const label = world === 'all' ? 'Alle Welten' : (franchiseOf(world) || world);
      return { type: 'nosama', url: withQuery, name: label ? shop + ' \u00b7 ' + label : shop, shopName: shop, html };
    }
    if (isWix(html)) {
      const cat = wixCategory(html);
      return { type: 'wix', url: clean, name: cat ? shop + ' \u00b7 ' + cat : shop, shopName: shop, html };
    }
    if (isSoftridge(html)) {
      const h1 = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || ''));
      return { type: 'softridge', url: clean, cat: srApi(html), name: h1 ? shop + ' \u00b7 ' + h1 : shop, shopName: shop, html };
    }
    if (isManor(html)) {
      const h1 = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || ''));
      const u2 = new URL(withQuery); u2.searchParams.delete('page');
      return { type: 'manor', url: u2.toString(), name: h1 ? shop + ' \u00b7 ' + h1 : shop, shopName: shop, html };
    }
    // Zuletzt: liefert der Shop seine Liste als JSON-LD mit? Das koennen auch
    // Laeden, deren Markup wir nicht kennen.
    if (isJsonLdList(html) || isJsonLdProduct(html)) {
      const u2 = new URL(withQuery);
      // Sortieren verbietet brack.ch in seiner robots.txt; geblaettert wird ohnehin selbst.
      u2.searchParams.delete('sortProducts'); u2.searchParams.delete('page');
      const h1 = decodeEntities(stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || ''));
      const label = isJsonLdList(html) && h1 ? shop + ' \u00b7 ' + h1 : shop;
      return { type: 'jsonld', url: u2.toString(), name: label, shopName: shop, html };
    }
  }
  // Manche Shops (z. B. coop-city.ch) lassen gar keine automatischen Abrufe zu und
  // antworten mit einer Captcha-Seite. Das ist kein unbekannter Shop-Typ, sondern eine
  // bewusste Sperre des Betreibers – die Meldung soll das auch so sagen.
  if (blocked) throw new Error(host + ' sperrt automatische Abrufe (' + blocked.replace(/^.*?: /, '') + '). Dieser Shop lässt sich nicht überwachen.');
  // War der Laden schlicht nicht erreichbar, ist das kein unbekannter Shop-Typ.
  // Das zu verwechseln kostet nur Sucherei: "522" heisst, der Shop ist gerade weg.
  if (down) throw new Error(host + ' war nicht erreichbar (' + down.replace(/^.*?: /, '') + ') – bitte später nochmal versuchen');
  throw new Error('Shop-Typ nicht erkannt (unterstützt: Shopify, WooCommerce, Shopware, PrestaShop, ePages, CS-Cart, SumUp, JSON-LD, wog.ch)');
}


// ---- Einzelne Produkte beobachten ("Beobachten" in der App) ----
// Ein beobachtetes Produkt ist eine Quelle mit  item: { handle | slug | pid, vid? }  (genau 1 Produkt/Variante).
const absUrl = (u) => (u && u.startsWith('//') ? 'https:' + u : u || '');
const priceOfJs = (v) => {
  const p = v.price;
  if (typeof p === 'number') return p / 100;
  const t = String(p);
  return t.includes('.') ? parseFloat(t) : parseFloat(t) / 100;
};

// Shopify  /products/<handle>.js  ->  eine Variante (vid) oder das ganze Produkt (günstigster Preis / irgendeine verfügbar)
function shopifyJsItems(j, origin, vid, all) {
  const vs = j.variants || [];
  const hay = [j.title, j.type, j.vendor, (j.tags || []).join(' ')].join(' ');
  const base = { g: franchiseOf(hay), i: shopifyImg(absUrl(j.featured_image || (j.images && j.images[0]))) };
  const one = (v, label) => Object.assign({ id: String(v.id), t: label ? j.title + ' – ' + v.title : j.title, p: priceOfJs(v), a: v.available ? 1 : 0, u: origin + '/products/' + j.handle + '?variant=' + v.id, vid: v.id }, base);
  if (vid) { const v = vs.find((x) => String(x.id) === String(vid)); return v ? [one(v, vs.length > 1)] : []; }
  if (all) return vs.map((v) => one(v, vs.length > 1));
  const ps = vs.map(priceOfJs).filter((x) => x >= 0);
  return [Object.assign({ id: String(j.id), t: j.title, p: ps.length ? Math.min(...ps) : null, a: vs.some((v) => v.available) ? 1 : 0, u: origin + '/products/' + j.handle }, base)];
}

async function getHtml(url) {
  const res = await fetch(url, { headers: { 'User-Agent': WATCH_UA, Accept: 'text/html' } });
  if (!res.ok) throw new Error(new URL(url).host + ': HTTP ' + res.status);
  const html = await res.text();
  return { html, bytes: html.length };
}
function wogItemFromHtml(html, url) {
  const m = (re) => { const x = html.match(re); return x ? x[1].trim() : ''; };
  const pid = m(/var productID = (\d+)/);
  const price = parseFloat(m(/itemprop="price" content="([\d.]+)"/));
  const avail = m(/itemprop="availability" href="\s*([^"]+)"/);
  if (!pid || !(price >= 0)) throw new Error('wog.ch: Produktseite nicht lesbar');
  const title = decodeEntities(m(/<meta property="og:title" content="([^"]+)"/)).replace(/\s*\[[^\]]+\]\s*$/, '');
  return { id: pid, pid, t: title, p: price > 0 ? price : null, a: /InStock|PreOrder|LimitedAvailability|OnlineOnly/i.test(avail) ? 1 : 0, u: url, i: m(/<meta property="og:image" content="([^"]+)"/), g: franchiseOf(title) };
}

async function fetchItem(src) {
  const it = src.item, origin = new URL(src.url).origin;
  if (src.type === 'shopify') {
    const { data, bytes } = await getJson(origin + '/products/' + it.handle + '.js');
    const list = shopifyJsItems(data, origin, it.vid, false);
    if (!list.length) throw new Error('Produkt/Variante nicht mehr gefunden');
    return { list, pages: 1, bytes };
  }
  if (src.type === 'woocommerce') {
    const { data, bytes } = await getJson(wooApi(src) + '/products?slug=' + encodeURIComponent(it.slug));
    if (!Array.isArray(data) || !data[0]) throw new Error('Produkt nicht mehr gefunden');
    const x = wooNorm(data[0]); delete x.hay;
    return { list: [x], pages: 1, bytes };
  }
  if (src.type === 'epages') {
    const { data, bytes } = await getJson(epagesApi(src) + '/' + encodeURIComponent(it.pid));
    if (!data || !data.productId) throw new Error('Produkt nicht mehr gefunden');
    const x = epagesNorm(data, origin); delete x.hay;
    return { list: [x], pages: 1, bytes };
  }
  if (src.type === 'cscart') {
    const { html, bytes } = await getHtml(csClean(src.url));
    return { list: [csProduct(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'sumup') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [suProduct(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'shopware') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [swProduct(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'prestashop') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [psProduct(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'jsonld') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [ldProduct(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'epages6') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [e6Product(html, src.url)], pages: 1, bytes };
  }
  if (src.type === 'manor') {
    const { html, bytes } = await getHtml(src.url);
    return { list: [manorProduct(html, src.url)], pages: 1, bytes };
  }
  const { html, bytes } = await getHtml(src.url);
  return { list: [wogItemFromHtml(html, src.url)], pages: 1, bytes };
}

// Link prüfen: Produkt (evtl. mit Varianten), Kollektion/Shop (Auswahl anbieten) oder nicht unterstützt.
async function probeLink(raw) {
  let u;
  try { u = new URL(raw.includes('://') ? raw : 'https://' + raw); } catch (e) { throw new Error('keine gültige URL'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('keine gültige URL');
  const host = u.hostname.replace(/^www\./, '');
  const shop = host.replace(/\.(ch|com|de|eu|net|shop|store|site|li|at|io|online)$/, '');
  const path = decodeURIComponent(u.pathname).replace(/\/+$/, '');
  const tag = (list, type, name, extra) => list.map((x) => Object.assign({ type, shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: Object.assign({}, extra, x.vid ? { vid: x.vid } : {}) }, {}));

  // wog.ch
  if (/(^|\.)wog\.ch$/.test(host)) {
    const pm = path.match(/\/details\/product\/(\d+)/);
    if (pm) {
      const { html } = await getHtml(u.origin + u.pathname);
      const x = wogItemFromHtml(html, u.origin + u.pathname);
      return { kind: 'product', shop: 'World of Games', items: tag([x], 'wog', 'World of Games', { pid: x.pid }) };
    }
    const { list } = await fetchWog({ fr: [] });
    return { kind: 'collection', shop: 'World of Games', source: { url: raw }, items: list.slice(0, 12).map((x) => ({ type: 'wog', shop: 'World of Games', title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  // Shopify-Produkt
  const sm = path.match(/\/products\/([^/]+)$/);
  if (sm) {
    try {
      const { data } = await getJson(u.origin + '/products/' + sm[1] + '.js');
      if (data && Array.isArray(data.variants)) {
        const list = shopifyJsItems(data, u.origin, null, true);
        return { kind: 'product', shop, items: tag(list, 'shopify', shop, { handle: data.handle }) };
      }
    } catch (e) { if (/HTTP 429/.test(e.message)) throw e; }
  }

  // ePages-Produkt: /p/<slug>. Die productId steht im eingebetteten Zustand,
  // danach reicht fuer jede Pruefung die kleine JSON-Antwort zu dieser id.
  const em = path.match(/^\/p\/(.+)$/);
  if (em) {
    try {
      const { html } = await getHtml(u.origin + u.pathname);
      const st = epagesState(html);
      const prod = st && st.products && (st.products[em[1]] || Object.values(st.products)[0]);
      if (prod && prod.productId) {
        const name = (st.shop && (st.shop.title || st.shop.name)) || shop;
        const x = epagesNorm(prod, u.origin); delete x.hay;
        return { kind: 'product', shop: name, items: tag([x], 'epages', name, { pid: prod.productId }) };
      }
    } catch (e) { if (/HTTP 429/.test(e.message)) throw e; }
  }

  // Kollektion / Shop (Shopify oder WooCommerce) – oder WooCommerce-Produkt
  let det;
  try { det = await detectSource(raw); } catch (e) { det = null; }

  // CS-Cart: Produktseite und Kategorie stecken beide im HTML, das die
  // Erkennung schon geholt hat – kein zweiter Abruf noetig.
  if (det && det.type === 'cscart') {
    const csHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (csHtml.includes('ty-product-block')) {       // Produktseite
      const x = csProduct(csHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'cscart', name, { pid: x.pid }) };
    }
    const list = csItems(csHtml, u.origin).slice(0, 12);
    return { kind: 'collection', shop: det.name, source: { url: det.url },
      items: list.map((x) => ({ type: 'cscart', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id } })) };
  }

  if (det && det.type === 'nosama') {
    const nHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    const list = nosamaItems(nHtml, det.url).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'nosama', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'wix') {
    const wHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    const list = wixItems(wixList(wHtml), det.url, wixCategory(wHtml)).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'wix', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'softridge') {
    const name = det.shopName || shop;
    const { data } = await getJson(srPageUrl({ url: det.url, cat: det.cat }, 1));
    const list = srItems(data, det.url).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url, cat: det.cat },
      items: list.map((x) => ({ type: 'softridge', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'manor') {
    const mHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    const list = manorItems(mHtml);
    if (list.length === 1) {
      const x = manorProduct(mHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'manor', name, { pid: x.pid }) };
    }
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.slice(0, 12).map((x) => ({ type: 'manor', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'epages6') {
    const e6Html = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (isE6Detail(e6Html)) {
      const x = e6Product(e6Html, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'epages6', name, { pid: x.pid }) };
    }
    const list = e6Items(e6Html, det.url).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'epages6', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'jsonld') {
    const ldHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (!isJsonLdList(ldHtml)) {
      const x = ldProduct(ldHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'jsonld', name, { pid: x.pid }) };
    }
    const list = ldItems(ldHtml, det.url).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'jsonld', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'prestashop') {
    const psHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (isPsDetail(psHtml)) {
      const x = psProduct(psHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'prestashop', name, { pid: x.pid }) };
    }
    const list = psItems(psHtml).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'prestashop', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'shopware') {
    const swHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (isSwDetail(swHtml) && !isSwListing(swHtml)) {
      const x = swProduct(swHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'shopware', name, { pid: x.pid }) };
    }
    const list = swItems(swHtml).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'shopware', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }

  if (det && det.type === 'sumup') {
    const suHtml = det.html || (await getHtml(det.url)).html;
    const name = det.shopName || shop;
    if (isSumUpProduct(suHtml)) {
      const x = suProduct(suHtml, det.url);
      return { kind: 'product', shop: name, items: tag([x], 'sumup', name, { pid: x.pid }) };
    }
    const list = suItems(suHtml).slice(0, 12);
    return { kind: 'collection', shop: name, source: { url: det.url },
      items: list.map((x) => ({ type: 'sumup', shop: name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: x.id, url: x.u } })) };
  }
  if (det && det.type === 'shopify' && !sm) {
    const { data } = await getJson(shopifyApi({ url: det.url }) + '?limit=12');
    const list = (data.products || []).map((p) => shopifyJsItems(Object.assign({ type: p.product_type, vendor: p.vendor, featured_image: p.images && p.images[0] && p.images[0].src }, p, { variants: (p.variants || []).map((v) => Object.assign({}, v, { price: v.price })) }), u.origin, null, false)[0]);
    return { kind: 'collection', shop: det.name, source: { url: det.url }, items: list.map((x, i) => ({ type: 'shopify', shop: shop, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { handle: data.products[i].handle } })) };
  }
  // WooCommerce-Produkt: letzter Pfadteil = slug
  const slug = path.split('/').filter(Boolean).pop();
  if (slug) {
    try {
      const { data } = await getJson(u.origin + '/wp-json/wc/store/v1/products?slug=' + encodeURIComponent(slug));
      if (Array.isArray(data) && data[0]) {
        const x = wooNorm(data[0]); delete x.hay;
        return { kind: 'product', shop, items: tag([x], 'woocommerce', shop, { slug: data[0].slug }) };
      }
    } catch (e) { /* weiter */ }
  }
  if (det && det.type === 'woocommerce') {
    const { data } = await getJson(wooApi({ url: det.url }) + '/products?per_page=12' + (det.cat ? '&category=' + det.cat : ''));
    return { kind: 'collection', shop: det.name, source: { url: det.url }, items: data.map((p) => { const x = wooNorm(p); return { type: 'woocommerce', shop, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { slug: p.slug } }; }) };
  }
  if (det && det.type === 'epages') {
    const { data } = await getJson(epagesApi({ url: det.url }) + '?resultsPerPage=12&page=1' + (det.cat ? '&categoryId=' + det.cat : ''));
    return { kind: 'collection', shop: det.name, source: { url: det.url }, items: (data.products || []).map((p) => { const x = epagesNorm(p, u.origin); return { type: 'epages', shop: det.name, title: x.t, price: x.p, a: x.a, img: x.i, url: x.u, item: { pid: p.productId } }; }) };
  }
  throw new Error('Weder Produkt noch Kollektion erkannt – unterstützt sind Shopify, WooCommerce, Shopware, PrestaShop, ePages, CS-Cart, SumUp, JSON-LD und wog.ch');
}


// ---------- Web Push (VAPID + RFC 8291 "aes128gcm", ohne Bibliothek) ----------
// Die VAPID-Schlüssel erzeugt der Worker beim ersten Bedarf selbst und legt sie in KV ab.
const PUSH_KEY = 'watch:push';
const VAPID_KEY = 'watch:vapid';
const MAX_PUSH_DEVICES = 8;
const MAX_PUSH_EVENTS = 10;   // so viele Einzelnachrichten je Lauf, der Rest kommt gebündelt
const PUSH_HOSTS = /^https:\/\/([\w.-]+\.)?(googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)\//;
const te = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

async function getVapid(env) {
  const stored = await env.DB.get(VAPID_KEY);
  if (stored) return JSON.parse(stored);
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const v = { priv: await crypto.subtle.exportKey('jwk', kp.privateKey), pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)) };
  await env.DB.put(VAPID_KEY, JSON.stringify(v));
  return v;
}
async function vapidHeader(endpoint, v) {
  const head = b64u(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(te.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://ylau802.github.io/Buchhaltung-TCG/' })));
  const key = await crypto.subtle.importKey('jwk', v.priv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(head + '.' + claims));
  return 'vapid t=' + head + '.' + claims + '.' + b64u(sig) + ', k=' + v.pub;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
// Nutzlast für ein Gerät verschlüsseln (RFC 8291, ein Record).
async function encryptPush(sub, plaintext) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, secret, concat(te.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(plaintext, new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 0x10, 0]), new Uint8Array([asPub.length]), asPub, body);
}

async function readPush(env) {
  const s = await env.DB.get(PUSH_KEY);
  return s ? JSON.parse(s) : [];
}
const clip = (t, n) => (String(t).length > n ? String(t).slice(0, n - 1) + '…' : String(t));

// Eine Nachricht an alle angemeldeten Geräte; tote Abos (404/410) werden vermerkt.
async function pushOne(env, subs, v, msg, dead) {
  const payload = te.encode(JSON.stringify(msg));
  let sent = 0, failed = 0;
  await Promise.all(subs.map(async (sub) => {
    try {
      const res = await fetch(sub.endpoint, {
        method: 'POST',
        headers: { Authorization: await vapidHeader(sub.endpoint, v), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'normal' },
        body: await encryptPush(sub, payload),
      });
      if (res.ok) sent++;
      else { failed++; if (res.status === 404 || res.status === 410) dead.add(sub.endpoint); }
    } catch (e) { failed++; }
  }));
  return { sent, failed };
}

// Je Meldung eine eigene Benachrichtigung – nichts wird zusammengefasst.
// Nur wenn auf einen Schlag sehr viele Meldungen kommen, wird der Rest gebündelt:
// sonst stünden 40 Nachrichten gleichzeitig auf dem Handy und der Worker liefe
// in das Limit für Fremdabrufe pro Lauf.
async function sendPush(env, events, test) {
  const all = await readPush(env);
  const subs = all.slice(0, MAX_PUSH_DEVICES);
  if (!subs.length) return { devices: 0, sent: 0, failed: 0, messages: 0 };
  const v = await getVapid(env);
  const dead = new Set();
  const single = events.slice(0, MAX_PUSH_EVENTS);
  const rest = events.slice(MAX_PUSH_EVENTS);
  const pre = test ? 'Test: ' : '';
  const msgs = single.map((e, i) => ({
    t: clip(pre + KIND_LABEL[e.k] + (e.s ? ' · ' + e.s : '') + (e.l ? ' · ' + e.l : ''), 80),
    b: clip(clip(e.t, 90) + '\n' + describe(e), 220),
    // eigener tag je Meldung, sonst ersetzen sich die Nachrichten auf dem Gerät
    g: 'ev-' + (e.k || '') + '-' + (e.id || '') + '-' + i + '-' + (e.at || Date.now()),
  }));
  if (rest.length) {
    msgs.push({
      t: clip(pre + '+' + rest.length + ' weitere Meldungen', 80),
      b: clip(rest.slice(0, 3).map((e) => clip(e.t, 60)).join('\n') + (rest.length > 3 ? '\n…' : ''), 220),
      g: 'ev-rest-' + Date.now(),
    });
  }
  let sent = 0, failed = 0;
  for (const msg of msgs) {
    const r = await pushOne(env, subs, v, msg, dead);
    sent += r.sent; failed += r.failed;
  }
  if (dead.size) await env.DB.put(PUSH_KEY, JSON.stringify(all.filter((x) => !dead.has(x.endpoint))));
  return { devices: subs.length, sent, failed, messages: msgs.length };
}

// ---- Vergleich: neu / Preis / wieder verfügbar ----
// silentFrom: ab dieser Stelle in der Liste gilt ein unbekannter Artikel nicht als neu.
// Gebraucht, wenn dieser Lauf tiefer gelesen hat als je zuvor: was dort auftaucht,
// steht laengst im Laden, der Monitor hat nur nie so weit geschaut. Die Listen sind
// nach "Neuste zuerst" sortiert, echte Neuheiten stehen also vorne.
function diff(src, list, prev, init, now, silentFrom) {
  const next = Object.assign({}, prev);
  const events = [];
  const limit = silentFrom == null ? Infinity : silentFrom;
  let i = -1;
  for (const it of list) {
    i++;
    const old = prev[it.id];
    let keep = null;   // Bezugspreis, der stehen bleibt (siehe unten)
    if (init) {
      const ev = { s: src.shop || src.name, id: it.id, t: it.t, p: it.p, a: it.a, u: it.u, i: it.i, g: it.g, l: langOf(it.t, it.u, src.url), at: now };
      if (!old) { if (i < limit) events.push(Object.assign({ k: 'new' }, ev)); }
      else {
        const moved = old[0] != null && it.p != null ? it.p - old[0] : 0;
        if (it.a === 1 && Math.abs(moved) > PRICE_MIN + 0.004) {
          events.push(Object.assign({ k: 'price', o: old[0] }, ev));
        } else if (it.a === 1 && moved) {
          // Kleiner Ausschlag (bei Importshops oft taeglich der Wechselkurs): nicht melden,
          // aber den alten Preis als Bezugspunkt behalten. So faellt ein echtes Klettern
          // in Ein-Franken-Schritten trotzdem auf, sobald der Franken voll ist.
          keep = old[0];
        }
        if (old[1] === 0 && it.a === 1) events.push(Object.assign({ k: 'stock' }, ev));
      }
    }
    next[it.id] = [keep == null ? it.p : keep, it.a];
  }
  return { next, events };
}

// Preisaenderungen werden nur bei verfuegbaren Artikeln gemeldet und erst, wenn sich
// der Preis um mehr als diesen Betrag bewegt hat – darunter ist es bei Importshops
// meist nur der Wechselkurs.
const PRICE_MIN = 1;
const KIND_LABEL = { new: 'Neu', price: 'Preisänderung', stock: 'Wieder verfügbar' };
function describe(ev) {
  if (ev.k === 'price') return chf(ev.o) + ' → ' + chf(ev.p) + (ev.p < ev.o ? ' ▼' : ' ▲');
  return chf(ev.p) + (ev.k === 'new' ? (ev.a ? ' · verfügbar' : ' · ausverkauft') : ' · wieder verfügbar');
}

// Eine Prüfrunde: die am längsten ungeprüften Quellen, solange das Budget (Anfragen/Datenmenge)
// reicht. Neue Quellen: erster Lauf nur Schnappschuss, keine Ereignisse.
// only = Liste von Quellen-IDs: dann wird nur die eingelesen. Das braucht die App
// gleich nach dem Hinzufügen – sonst wartet man dort auf eine ganze Runde über
// alle Quellen, nur um eine einzige neue zu sehen.
async function runWatch(env, only) {
  const now = new Date().toISOString();
  const cfg = await readCfg(env);
  const state = await readState(env);
  const pick = only && only.length ? new Set(only) : null;

  // Einmalig nach dem Preis-Fix: Quellen, deren Preise als Text dastehen, still
  // neu einlesen. Sonst meldete der naechste Lauf die Korrektur (299.95 -> 2299.95)
  // als Preisaenderung, obwohl sich am Laden nichts geaendert hat.
  const FIX = 'textpreis-1';
  if (state.fix !== FIX) {
    for (const s of cfg.sources) if (s.type === 'sumup' || s.type === 'prestashop') resetSource(state, s.id);
    state.fix = FIX;
  }
  // Einmalig: die Flut falscher "Neu"-Meldungen aufraeumen, die entstand, als die
  // Shopware-Quellen auf die Listen-Schnittstelle umstiegen und auf einen Schlag
  // viel mehr Artikel sahen. Betroffen ist nur, was in den letzten drei Stunden
  // als "neu" von einem Shopware-Shop gemeldet wurde.
  const FIX2 = 'shopware-flut-1';
  if (state.fix2 !== FIX2) {
    const sw = new Set(cfg.sources.filter((s) => s.type === 'shopware').map((s) => s.shop || s.name));
    const since = Date.parse(now) - 3 * 60 * 60 * 1000;
    if (sw.size && Array.isArray(state.events)) {
      state.events = state.events.filter((e) => !(e.k === 'new' && sw.has(e.s) && Date.parse(e.at) >= since));
    }
    state.fix2 = FIX2;
  }

  const todo = cfg.sources.filter((s) => !s.off && (!pick || pick.has(s.id)))
    .sort((a, b) => ((state.src[a.id] || {}).lastCheck || '').localeCompare((state.src[b.id] || {}).lastCheck || ''));
  const batch = [];
  let pagesLeft = RUN_SUBREQ, bytesLeft = RUN_BYTES;
  const tNow = Date.parse(now);
  // Je Shop gilt ein eigenes Budget: mehrere Quellen desselben Ladens teilen es sich,
  // der Rest kommt im naechsten Lauf dran (die am laengsten ungeprueften zuerst).
  // Sonst fragt der Monitor bei sechs Quellen eines Shops zwoelfmal in fuenf Minuten an,
  // und genau das quittiert goodgamesbern.ch mit HTTP 403.
  const perHost = new Map();
  for (const s of todo) {
    const h = state.src[s.id] || {};
    // Hat der Shop gerade dichtgemacht, erst nach der Ruhepause wieder anklopfen.
    if (h.cool && tNow < Date.parse(h.cool)) continue;
    const pg = h.pages || 1, by = h.bytes || 300000;
    const host = new URL(s.url).hostname;
    const used = perHost.get(host) || 0;
    if (used && used + pg > HOST_PAGES) continue;
    if (batch.length && (pg > pagesLeft || by > bytesLeft)) continue;
    batch.push(s); pagesLeft -= pg; bytesLeft -= by; perHost.set(host, used + pg);
  }

  // Höchstens 4 gleichzeitig: Shopify & Co. drosseln (HTTP 429), wenn eine IP viele Shops auf einmal abfragt.
  // Dabei pro Host nur eine Anfrage zur Zeit – mehrere Kollektionen desselben Shops liefen sonst
  // parallel gegen denselben Server und genau das quittiert er mit 429.
  const byHost = new Map();
  for (const s of batch) {
    const h = new URL(s.url).hostname;
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h).push(s);
  }
  const queues = [...byHost.values()];
  const results = [];
  const deep = { n: 0 };
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(4, queues.length) }, async () => {
    while (next < queues.length) {
      let done = 0;
      for (const s of queues[next++]) {
        if (done++) await sleep(HOST_PAUSE);   // nicht zwei Quellen desselben Shops am Stueck
        const h0 = state.src[s.id] || {};
        const win = WINDOW[s.type];
        let plan, isFull = false;
        if (win) {
          // Seite 1 plus das wandernde Fenster
          const cur = Math.max(2, h0.cursor || 2);
          plan = [1];
          for (let k = 0; k < win; k++) plan.push(cur + k);
        } else {
          // Schnittstellen-Shops: eine Quelle je Lauf darf tiefer schauen
          const due = !h0.lastFull || Date.parse(now) - Date.parse(h0.lastFull) > FULL_EVERY;
          const full = due && deep.n < 1;
          if (full) deep.n++;
          plan = (PAGE_BUDGET[s.type] || PAGE_BUDGET.shopify)[full ? 1 : 0];
          isFull = full;
        }
        // Shopware lernt beim ersten Lauf die Listen-Schnittstelle des Shops; sie
        // liegt danach im Zustand der Quelle und wird hier wieder mitgegeben.
        const sx = s.type === 'shopware' && !s.cat && h0.sw ? Object.assign({}, s, { cat: h0.sw }) : s;
        try { results.push({ s, full: win ? true : isFull, win, r: await fetchSource(sx, plan) }); }
        catch (e) { results.push({ s, err: e.message }); }
      }
    }
  }));

  const events = [];
  const commits = []; // [sourceId, nextSnap, st, nEvents]
  for (const { s, r, err, full, win } of results) {
    const st = Object.assign({}, state.src[s.id], { lastCheck: now });
    if (err) {
      if (BLOCKED.test(err)) {
        // Der Shop drosselt uns. Nicht weiter anklopfen, sondern ruhen – und bei jeder
        // weiteren Sperre doppelt so lange. Der zuletzt bekannte Stand bleibt stehen.
        const n = Math.min((st.coolN || 0) + 1, 5);
        const wait = Math.min(COOL_AFTER_BLOCK * Math.pow(2, n - 1), COOL_MAX);
        st.coolN = n;
        st.cool = new Date(Date.parse(now) + wait).toISOString();
        const mins = Math.round(wait / 60000);
        st.lastError = new URL(s.url).hostname + ' drosselt gerade (' + err.replace(/^.*?: /, '') + ') – nächster Versuch in '
          + (mins >= 120 ? Math.round(mins / 60) + ' Stunden' : mins + ' Minuten');
      } else if (/HTTP 5\d\d/.test(err)) {
        // 5xx liegt beim Shop, nicht bei uns (530 schickt Cloudflare, wenn der
        // Laden hinter dem Schutzschild gerade nicht antwortet). Beim nächsten
        // Lauf wird es einfach wieder versucht, der letzte Stand bleibt stehen.
        st.lastError = new URL(s.url).hostname + ' war kurz nicht erreichbar ('
          + err.replace(/^.*?: /, '') + ') – wird beim nächsten Lauf erneut versucht';
      } else st.lastError = err;
      state.src[s.id] = st; continue;
    }
    const snap = state.snap[s.id] || {};
    // Beim wandernden Fenster koennen neue Artikel nur auf Seite 1 stehen (die Listen
    // sind nach "Neuste zuerst" sortiert). Was das Fenster weiter hinten zutage foerdert,
    // steht laengst im Laden und wird still uebernommen.
    // Bei den anderen gilt dasselbe, sobald ein Lauf tiefer liest als je zuvor.
    const deeper = r.pages > (st.seenPages || 0);
    // Zweite Sicherung, unabhaengig von der Zahl der Seiten: Hat dieser Lauf mehr
    // Artikel gesehen als je einer zuvor, sind die zusaetzlichen nicht neu - wir
    // haben nur nie so weit geschaut. Genau das passierte bei amazingtoys, als der
    // Monitor auf die Listen-Schnittstelle umstieg und Seite 1 von 24 auf 96
    // Artikel wuchs: 72 Artikel, die laengst im Laden standen, galten als Neuheit.
    // Fuer Quellen ohne gemerkte Tiefe dient der bisherige Stand als Mass.
    const known = st.depth != null ? st.depth : Object.keys(snap).length;
    const limits = [];
    if (win) limits.push(r.firstCount);
    else if (deeper) limits.push(Object.keys(snap).length);
    if (known && r.list.length > known) limits.push(known);
    const silentFrom = limits.length ? Math.min(...limits) : null;
    const d = diff(s, r.list, snap, !!st.init, now, silentFrom);
    st.seenPages = Math.max(st.seenPages || 0, r.pages);
    st.depth = Math.max(known, r.list.length);
    // Fenster weiterschieben; hinter der letzten Seite wieder vorne anfangen
    if (win) st.cursor = r.end ? 2 : Math.max(2, st.cursor || 2) + win;
    // Ein Schnelldurchlauf liest absichtlich nur die neuesten Seiten – das ist kein Fehler.
    // Gemeldet wird nur, wenn auch der volle Durchlauf nicht bis zum Ende kam.
    Object.assign(st, { lastOk: now, lastError: full && r.truncated ? 'sehr grosse Kategorie – geprüft werden die ' + r.list.length + ' neuesten Artikel' : null,
      count: win ? Math.max(st.count || 0, Object.keys(d.next).length) : r.list.length,
      pages: r.pages, bytes: r.bytes, init: true });
    if (full) st.lastFull = now;
    // Beim ersten Mal die vollen Durchlaeufe ueber die Stunde verteilen, damit nicht
    // alle Quellen eines Shops immer im selben Lauf in die Tiefe gehen.
    else if (!st.lastFull) st.lastFull = new Date(Date.parse(now) - Math.floor(Math.random() * FULL_EVERY)).toISOString();
    if (st.cool) delete st.cool;
    if (st.coolN) delete st.coolN;
    if (s.item && r.list[0]) st.cur = { p: r.list[0].p, a: r.list[0].a };
    if (r.cat && r.cat !== st.sw) st.sw = r.cat;
    commits.push([s.id, d.next, st, d.events.length]);
    events.push(...d.events);
  }

  // Push ist der einzige Weg, auf dem eine Meldung aufs Handy kommt. Kommt der
  // Versand gar nicht zustande, bleibt der alte Schnappschuss der betroffenen
  // Quellen stehen, damit der nächste Lauf dieselben Ereignisse erneut meldet.
  // Ohne angemeldetes Gerät ist das kein Fehler: sendPush meldet dann schlicht null.
  let pushErr = null;
  if (events.length) {
    try { await sendPush(env, events, false); } catch (e) { pushErr = e.message; }
  }
  for (const [id, next, st, n] of commits) {
    if (pushErr && n) { st.lastError = 'Push fehlgeschlagen, neuer Versuch folgt'; state.src[id] = st; continue; }
    state.snap[id] = next; state.src[id] = st;
  }
  if (!pushErr && events.length) state.events = events.concat(state.events).slice(0, EVENTS_KEEP);
  // Nur bei einer vollen Runde: "letzter Lauf" und das Aufräumen gelöschter Quellen.
  // Eine gezielte Prüfung einzelner Quellen sagt über die übrigen nichts aus.
  if (!pick) {
    state.lastRun = now;
    state.lastError = pushErr;
    const ids = new Set(cfg.sources.map((s) => s.id));
    for (const k of Object.keys(state.snap)) if (!ids.has(k)) { delete state.snap[k]; delete state.src[k]; }
  }
  await env.DB.put(STATE_KEY, JSON.stringify(state));
  return { cfg, state };
}

async function handleNews(request, env, url, tokenHash) {
  const rec = await readVault(env);
  if (!rec) return text('kein Vault angelegt', 409);
  if (rec.tokenHash !== tokenHash) return text('forbidden', 403);

  const pushN = (await readPush(env)).length;
  const view = (cfg, st) => json({
    sources: cfg.sources.map((s) => Object.assign({}, s, { fr: srcFr(s), st: st.src[s.id] || null })),
    catalog: CATALOG.map((c) => c[0]), custom: cfg.customFr || [],
    events: (st.events || []).slice(0, 300),
    lastRun: st.lastRun || null, lastError: st.lastError || null, push: pushN,
  });
  const path = url.pathname, m = request.method;

  if (path === '/news' && m === 'GET') return view(await readCfg(env), await readState(env));
  if (path === '/news/check' && m === 'POST') {
    let only = null;
    try { const b = await request.json(); if (b && Array.isArray(b.ids)) only = b.ids.map(String).slice(0, 8); } catch (e) { /* ohne Body: volle Runde */ }
    const r = await runWatch(env, only);
    return view(r.cfg, r.state);
  }

  if (path === '/news/push/key' && m === 'GET') return json({ key: (await getVapid(env)).pub });
  if (path === '/news/push' && m === 'POST') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    const sub = body && body.sub;
    if (!sub || typeof sub.endpoint !== 'string' || !PUSH_HOSTS.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth)
      return json({ error: 'ungültiges Push-Abo' }, 400);
    const subs = (await readPush(env)).filter((x) => x.endpoint !== sub.endpoint);
    subs.unshift({ endpoint: sub.endpoint, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) }, at: new Date().toISOString() });
    await env.DB.put(PUSH_KEY, JSON.stringify(subs.slice(0, MAX_PUSH_DEVICES)));
    return json({ ok: true, devices: Math.min(subs.length, MAX_PUSH_DEVICES) });
  }
  if (path === '/news/push/remove' && m === 'POST') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    const subs = (await readPush(env)).filter((x) => x.endpoint !== (body && body.endpoint));
    await env.DB.put(PUSH_KEY, JSON.stringify(subs));
    return json({ ok: true, devices: subs.length });
  }
  if (path === '/news/push/test' && m === 'POST') {
    const st = await readState(env);
    const evs = st.events.length ? st.events.slice(0, 2)
      : [{ k: 'new', s: 'Testshop', t: 'Beispiel-Produkt (Test-Push)', p: 19.9, a: 1, u: '' }];
    try {
      const r = await sendPush(env, evs, true);
      if (!r.devices) return json({ error: 'Kein Gerät für Push angemeldet' }, 400);
      return json(r);
    } catch (e) { return json({ error: e.message }, 502); }
  }

  if (path === '/news/watch/probe' && m === 'POST') {
    await readCfg(env); // Katalog laden
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    try { return json(await probeLink(String(body.url || '').trim())); }
    catch (e) { return json({ error: e.message }, 422); }
  }

  if (path === '/news/watch' && m === 'POST') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    const cfg = await readCfg(env);
    const st = await readState(env);
    const now = new Date().toISOString();
    const out = [];
    for (const x of (Array.isArray(body.items) ? body.items : []).slice(0, 20)) {
      try {
        if (!['shopify', 'woocommerce', 'wog'].includes(x.type)) throw new Error('Typ nicht unterstützt');
        const it = x.item || {};
        const ref = { handle: it.handle && String(it.handle), slug: it.slug && String(it.slug), pid: it.pid && String(it.pid), vid: it.vid && String(it.vid) };
        if (!(ref.handle || ref.slug || ref.pid)) throw new Error('Produkt unklar');
        const pu = new URL(String(x.url));
        if (!/^https?:$/.test(pu.protocol)) throw new Error('keine gültige URL');
        if (cfg.sources.length >= MAX_SOURCES) throw new Error('maximal ' + MAX_SOURCES + ' Quellen');
        const src = { id: crypto.randomUUID().slice(0, 8), name: String(x.title || '').slice(0, 120), shop: String(x.shop || pu.hostname).slice(0, 60), url: pu.origin + (x.type === 'wog' ? pu.pathname : ''), type: x.type, fr: [], item: ref, img: String(x.img || '').slice(0, 300) };
        if (cfg.sources.some((s) => srcKey(s) === srcKey(src))) throw new Error('schon vorhanden');
        cfg.sources.push(src);
        // Stand von der Prüfung übernehmen -> erste Änderung wird schon erkannt
        const price = x.price == null ? null : Number(x.price);
        st.snap[src.id] = { x: [price, x.a ? 1 : 0] };
        st.src[src.id] = { init: true, lastCheck: now, lastOk: now, count: 1, pages: 1, bytes: x.type === 'wog' ? 1100000 : 8000, cur: { p: price, a: x.a ? 1 : 0 } };
        out.push({ ok: true, id: src.id });
      } catch (e) { out.push({ ok: false, error: e.message }); }
    }
    await env.DB.put(CFG_KEY, JSON.stringify(cfg));
    await env.DB.put(STATE_KEY, JSON.stringify(st));
    return json({ results: out });
  }

  // Eigene Franchises: Name + Stichwörter (Titel/Typ/Hersteller des Produkts werden danach durchsucht)
  if (path === '/news/franchises' && m === 'PUT') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    const cfg = await readCfg(env);
    const builtin = BUILTIN_FR.map((c) => c[0].toLowerCase());
    const seen = new Set(builtin), custom = [];
    for (const c of (Array.isArray(body.custom) ? body.custom : []).slice(0, 20)) {
      const name = String((c && c.name) || '').trim().slice(0, 40);
      const kw = (Array.isArray(c && c.kw) ? c.kw : []).map((k) => String(k).trim().slice(0, 40)).filter(Boolean).slice(0, 8);
      if (!name || seen.has(name.toLowerCase())) continue;
      seen.add(name.toLowerCase()); custom.push({ name, kw: kw.length ? kw : [name] });
    }
    // Entfernte eigene Franchises aus den Quellen streichen (und diese still neu einlesen)
    const alive = new Set(custom.map((c) => c.name)), st = await readState(env);
    const removed = (cfg.customFr || []).map((c) => c.name).filter((n) => !alive.has(n));
    for (const src of cfg.sources) {
      const fr = srcFr(src);
      if (fr.some((n) => removed.includes(n))) {
        src.fr = fr.filter((n) => !removed.includes(n)); delete src.filter; resetSource(st, src.id);
        if (!src.fr.length) src.off = true; // sonst würde plötzlich ALLES gemeldet
      }
    }
    // Stichwörter geändert -> betroffene Quellen still neu einlesen
    for (const c of custom) {
      const old = (cfg.customFr || []).find((o) => o.name === c.name);
      if (old && JSON.stringify(old.kw) !== JSON.stringify(c.kw)) for (const src of cfg.sources) if (srcFr(src).includes(c.name)) resetSource(st, src.id);
    }
    cfg.customFr = custom; setCatalog(cfg);
    await env.DB.put(CFG_KEY, JSON.stringify(cfg)); await env.DB.put(STATE_KEY, JSON.stringify(st));
    return view(cfg, st);
  }

  if (path === '/news/sources' && m === 'POST') {
    let body;
    try { body = await request.json(); } catch (e) { return text('bad json', 400); }
    const urls = (Array.isArray(body.urls) ? body.urls : []).map((x) => String(x).trim()).filter(Boolean).slice(0, 8);
    // Optional: eigener Name je URL, gleiche Reihenfolge wie urls. Leer = Name des Shops.
    const names = (Array.isArray(body.names) ? body.names : []).map((x) => String(x || '').trim().slice(0, 60));
    const cfg = await readCfg(env);
    const results = [];
    for (let k = 0; k < urls.length; k++) {
      const raw = urls[k];
      try {
        if (cfg.sources.length >= MAX_SOURCES) throw new Error('maximal ' + MAX_SOURCES + ' Quellen');
        const d = await detectSource(raw);
        if (cfg.sources.some((s) => srcKey(s) === srcKey(d))) throw new Error('schon vorhanden');
        const id = d.type === 'wog' ? 'wog' : crypto.randomUUID().slice(0, 8);
        let readable = d.url; try { readable = decodeURIComponent(d.url); } catch (e) { /* roh lassen */ }
        // Auswahl aus der App; ist die Kollektion schon per URL auf ein Franchise eingegrenzt (z. B. /pokemon), kein Filter.
        const known = CATALOG.map((c) => c[0]);
        let fr = Array.isArray(body.fr) ? body.fr.filter((n) => known.includes(n)) : DEFAULT_FR.slice();
        if (CATALOG.some(([, re]) => re.test(readable))) fr = [];
        const name = names[k] || d.name;
        cfg.sources.push(Object.assign({ id, name, url: d.url, type: d.type, fr }, d.cat ? { cat: d.cat } : {}));
        results.push({ url: raw, ok: true, id, name, type: d.type, fr });
      } catch (e) { results.push({ url: raw, ok: false, error: e.message }); }
    }
    await env.DB.put(CFG_KEY, JSON.stringify(cfg));
    return json({ results });
  }

  const sm = path.match(/^\/news\/sources\/([\w-]+)$/);
  if (sm) {
    const cfg = await readCfg(env);
    const i = cfg.sources.findIndex((s) => s.id === sm[1]);
    if (i < 0) return text('not found', 404);
    if (m === 'DELETE') cfg.sources.splice(i, 1);
    else if (m === 'PUT') {
      let body;
      try { body = await request.json(); } catch (e) { return text('bad json', 400); }
      const s = cfg.sources[i];
      if (typeof body.name === 'string' && body.name.trim()) s.name = body.name.trim().slice(0, 60);
      if (typeof body.off === 'boolean') s.off = body.off;
      if (Array.isArray(body.fr)) {
        const known = CATALOG.map((c) => c[0]);
        s.fr = body.fr.filter((n) => known.includes(n)); delete s.filter;
        const st = await readState(env); resetSource(st, s.id); await env.DB.put(STATE_KEY, JSON.stringify(st));
      }
    } else return text('method not allowed', 405);
    await env.DB.put(CFG_KEY, JSON.stringify(cfg));
    return view(cfg, await readState(env));
  }
  return text('not found', 404);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return text('', 204);
    if (!env.DB) return text('KV binding "DB" fehlt', 500);

    const url = new URL(request.url);
    const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!token) return text('missing token', 401);
    const tokenHash = await sha256hex(token);

    if (url.pathname === '/vault') return handleVault(request, env, tokenHash);
    if (url.pathname.startsWith('/files/')) return handleFiles(request, env, url, tokenHash);
    if (url.pathname === '/news' || url.pathname.startsWith('/news/')) return handleNews(request, env, url, tokenHash);
    return text('not found', 404);
  },

  async scheduled(event, env, ctx) {
    if (env.DB) ctx.waitUntil(runWatch(env));
  },
};
