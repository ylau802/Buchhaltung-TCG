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
  event.waitUntil(self.registration.showNotification(d.t || 'YL News', {
    body: d.b || 'Neue Meldungen im News-Dashboard.',
    icon: 'icons/icon-192.png',
    badge: 'icons/badge-mono-96.png',
    tag: d.g || 'yl-news',
    renotify: true,
    // p = wichtig (Vorverkauf): bleibt stehen, bis man sie wegtippt, und vibriert
    // anders als der Rest. Alles andere verschwindet wie gewohnt von selbst.
    requireInteraction: !!d.p,
    vibrate: d.p ? [120, 60, 120, 60, 240] : [120],
    data: { go: 'news' },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
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
