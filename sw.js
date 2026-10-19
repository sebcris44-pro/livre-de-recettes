/* Fonctionnement hors connexion.
   - l'application : en cache, renouvelée quand sa version change (remplacée à la publication) ;
   - livre.json et recettes.bin : réseau d'abord, sinon la dernière version enregistrée ;
   - photos : leur nom est l'empreinte du contenu, elles ne changent jamais -> cache d'abord. */
const VERSION = "d696b9836488";
const APP = "app-" + VERSION, DONNEES = "donnees", PHOTOS = "photos";
const FICHIERS = ["./", "index.html", "app.css", "app.js", "manifest.webmanifest", "icone-192.png", "icone-512.png", "icone-180.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(APP).then((c) => c.addAll(FICHIERS.map((f) => new Request(f, { cache: "reload" })))).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((cles) => Promise.all(cles.filter((c) => c.startsWith("app-") && c !== APP).map((c) => caches.delete(c))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.includes("/donnees/photos/")) {
    e.respondWith(caches.open(PHOTOS).then(async (c) => {
      const r = await c.match(e.request);
      if (r) return r;
      const net = await fetch(e.request);
      if (net.ok) c.put(e.request, net.clone());
      return net;
    }));
    return;
  }
  if (url.pathname.includes("/donnees/")) {
    e.respondWith(fetch(e.request).then((net) => {
      if (net.ok) { const copie = net.clone(); caches.open(DONNEES).then((c) => c.put(url.pathname, copie)); }
      return net;
    }).catch(() => caches.open(DONNEES).then((c) => c.match(url.pathname)).then((r) => r || Response.error())));
    return;
  }
  e.respondWith(caches.open(APP).then(async (c) => {
    const r = await c.match(e.request, { ignoreSearch: true }) || (url.pathname.endsWith("/") ? await c.match("index.html") : null);
    return r || fetch(e.request);
  }));
});
