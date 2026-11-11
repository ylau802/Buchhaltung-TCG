/* YL Service Worker – nur für Push-Benachrichtigungen (kein Caching: die Daten sind
   verschlüsselt und die App soll immer den aktuellen Stand laden). Der Worker schickt
   { t: Titel, b: Text, g: Kennung }; ein Klick öffnet die App direkt auf der News-Seite.
   g ist je Meldung verschieden, damit mehrere Nachrichten nebeneinander stehen
   bleiben und sich nicht gegenseitig ersetzen. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { /* kein JSON */ }
  // p = dringend (alles von wog.ch): mit Ton und Vibration, bleibt stehen, bis man
  // sie wegtippt – nur so blendet Android sie oben ein und weckt den Bildschirm.
  // Alle uebrigen Meldungen sind still: sie landen lautlos im Benachrichtigungs-
  // bereich und leuchten nichts auf, auch wenn die App auf "dringend" steht.
  const eilig = !!d.p;
  const opt = {
    body: d.b || 'Neue Meldungen im News-Dashboard.',
    icon: 'icons/icon-192.png',
    badge: 'icons/badge-mono-96.png',
    tag: d.g || 'yl-news',
    renotify: true,
    requireInteraction: eilig,
    silent: !eilig,
    data: { go: 'news', cart: d.c || '' },
  };
  // vibrate und silent zusammen lehnt Chrome ab.
  if (eilig) opt.vibrate = [120, 60, 120, 60, 240];
  if (eilig && d.c) opt.actions = [{ action: 'cart', title: 'In den Warenkorb' }];
  event.waitUntil(self.registration.showNotification(d.t || 'YL News', opt));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const cart = (event.notification.data || {}).cart;
  // "In den Warenkorb" oeffnet den Shop-Link; bestellt wird dort von Hand.
  if (event.action === 'cart' && cart) { event.waitUntil(self.clients.openWindow(cart)); return; }
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const open = wins.find((c) => c.url.startsWith(self.registration.scope));
    if (open) {
      await open.focus();
      open.postMessage({ go: 'news' });   // App schon offen: nur zur News-Seite wechseln
    } else {
      await self.clients.openWindow(self.registration.scope + '#news');
    }
  })());
});
