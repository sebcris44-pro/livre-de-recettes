/* Livre de recettes — application mobile (consultation).
   Les recettes sont chiffrées (AES-256-GCM) ; la clé est dérivée du mot de passe du livre (PBKDF2-SHA256)
   et gardée sur l'appareil sous forme non exportable. Rien n'est envoyé nulle part. */
"use strict";

const $app = document.getElementById("app");
const ETAT = {
  cle: null, livre: null, recettes: [], parId: new Map(), infos: null,
  recherche: "", categorie: "", filtres: { favoris: false, temps: 0, note: 0, tags: [] },
  photos: new Map(), installation: null, retour: "#/",
};
const LS = {
  lire(cle, defaut) { try { const v = localStorage.getItem("lr_" + cle); return v === null ? defaut : JSON.parse(v); } catch (e) { return defaut; } },
  ecrire(cle, v) { try { localStorage.setItem("lr_" + cle, JSON.stringify(v)); } catch (e) { /* stockage indisponible */ } },
};

/* ---------- Outils ---------- */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const normaliser = (s) => String(s || "").toLowerCase().replace(/œ/g, "oe").replace(/æ/g, "ae")
  .normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/\s+/g, " ").trim();
const pluriel = (n, mot) => `${n} ${mot}${n > 1 ? "s" : ""}`;
function toast(texte) {
  const t = document.getElementById("toast");
  t.textContent = texte; t.classList.add("visible");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("visible"), 2600);
}
function duree(minutes) {
  if (!minutes) return "";
  const h = Math.floor(minutes / 60), m = minutes % 60;
  return h && m ? `${h} h ${String(m).padStart(2, "0")}` : h ? `${h} h` : `${m} min`;
}
const etoiles = (n) => n ? "★".repeat(n) + "☆".repeat(5 - n) : "";

/* ---------- Fractions (mêmes règles que le programme PC) ---------- */
const pgcd = (a, b) => { a = Math.abs(a); b = Math.abs(b); while (b) [a, b] = [b, a % b]; return a || 1; };
const frac = (n, d = 1) => { const g = pgcd(n, d); return [n / g, d / g]; };
const fmul = (a, b) => frac(a[0] * b[0], a[1] * b[1]);
const fadd = (a, b) => frac(a[0] * b[1] + b[0] * a[1], a[1] * b[1]);
function formaterNombre([n, d]) {
  if (d === 1) return String(n);
  const v = n / d;
  if (v >= 10) return String(Math.round(v));
  if ([2, 3, 4].includes(d)) {
    const entier = Math.floor(n / d), reste = n % d;
    return entier ? `${entier} ${reste}/${d}` : `${reste}/${d}`;
  }
  return v.toFixed(1).replace(/\.?0+$/, "").replace(".", ",");
}
function quantite(ing, facteur) {
  if (!ing.m.length || (facteur[0] === facteur[1])) return ing.q;
  return ing.m.map((m) => (typeof m === "string" ? m : formaterNombre(fmul(m, facteur)))).join("");
}
function lireNombre(texte) {
  const t = texte.replace(",", ".").trim(), m = t.match(/^(\d+)\s+(\d+)\/(\d+)$/), f = t.match(/^(\d+)\/(\d+)$/);
  if (m) return fadd(frac(+m[1]), frac(+m[2], +m[3]));
  if (f) return frac(+f[1], +f[2]);
  const [e, d = ""] = t.split(".");
  return frac(+(e + d), 10 ** d.length);
}
// Comme sur le PC : la quantité recalculée est arrondie (« 33 cl ») avant d'être additionnée
const arrondi = (v) => lireNombre(formaterNombre(v));
function formaterTotal(v, unite) {
  const val = v[0] / v[1];
  if (unite === "g" && val >= 1000) return `${formaterNombre(fmul(v, [1, 1000]))} kg`;
  if (unite === "ml" && val >= 1000) return `${formaterNombre(fmul(v, [1, 1000]))} l`;
  if (unite === "ml" && val >= 100 && v[1] === 1 && v[0] % 10 === 0) return `${formaterNombre(fmul(v, [1, 10]))} cl`;
  return `${formaterNombre(v)} ${unite}`.trim();
}

/* ---------- Chiffrement ---------- */
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function deriverCle(motDePasse, sel, iterations) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(motDePasse), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: sel, iterations, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
async function dechiffrer(cle, tampon) {
  const o = new Uint8Array(tampon);
  if (o[0] !== 76 || o[1] !== 82 || o[2] !== 49) throw new Error("format");
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: o.slice(3, 15) }, cle, o.slice(15));
}
async function gunzip(tampon) {
  const flux = new Blob([tampon]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(flux).text();
}

/* ---------- Clé gardée sur l'appareil (IndexedDB, non exportable) ---------- */
function base() {
  return new Promise((ok, ko) => {
    const r = indexedDB.open("livre-recettes", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("cles");
    r.onsuccess = () => ok(r.result); r.onerror = () => ko(r.error);
  });
}
async function cleGardee(action, valeur) {
  try {
    const db = await base();
    return await new Promise((ok, ko) => {
      const tx = db.transaction("cles", action === "lire" ? "readonly" : "readwrite");
      const st = tx.objectStore("cles");
      const r = action === "lire" ? st.get("livre") : action === "oublier" ? st.delete("livre") : st.put(valeur, "livre");
      r.onsuccess = () => ok(r.result); r.onerror = () => ko(r.error);
    });
  } catch (e) { return null; }
}

/* ---------- Chargement du livre ---------- */
async function chargerInfos() {
  const r = await fetch("donnees/livre.json", { cache: "no-cache" });
  if (!r.ok) throw new Error("livre.json");
  return r.json();
}
async function ouvrirLivre(cle) {
  const r = await fetch("donnees/recettes.bin", { cache: "no-cache" });
  if (!r.ok) throw new Error("recettes.bin");
  const json = await gunzip(await dechiffrer(cle, await r.arrayBuffer()));
  const livre = JSON.parse(json);
  ETAT.cle = cle; ETAT.livre = livre; ETAT.recettes = livre.recettes;
  ETAT.parId = new Map(livre.recettes.map((x) => [x.id, x]));
  for (const x of ETAT.recettes) {
    x._ing = x.ing.map((i) => normaliser(i.n)).join(" | ");
    x._tags = (x.tags || []).map(normaliser);
  }
}
async function photo(id) {
  if (!id) return null;
  if (ETAT.photos.has(id)) return ETAT.photos.get(id);
  const promesse = (async () => {
    try {
      const r = await fetch(`donnees/photos/${id}.bin`);
      if (!r.ok) return null;
      const brut = await dechiffrer(ETAT.cle, await r.arrayBuffer());
      return URL.createObjectURL(new Blob([brut], { type: "image/jpeg" }));
    } catch (e) { return null; }
  })();
  ETAT.photos.set(id, promesse);
  return promesse;
}
const observateur = "IntersectionObserver" in window ? new IntersectionObserver((entrees) => {
  for (const e of entrees) {
    if (!e.isIntersecting) continue;
    observateur.unobserve(e.target);
    photo(e.target.dataset.photo).then((url) => { if (url) { e.target.style.backgroundImage = `url(${url})`; e.target.textContent = ""; } });
  }
}, { rootMargin: "300px" }) : null;
function chargerVignettes(racine) {
  racine.querySelectorAll("[data-photo]").forEach((el) => {
    if (observateur) observateur.observe(el);
    else photo(el.dataset.photo).then((url) => { if (url) { el.style.backgroundImage = `url(${url})`; el.textContent = ""; } });
  });
}

async function demarrer() {
  appliquerReglages();
  try {
    ETAT.infos = await chargerInfos();
  } catch (e) {
    $app.innerHTML = `<div class="connexion"><img src="icone-192.png" alt=""><h1>Livre de recettes</h1>
      <p>Impossible de charger le livre. Vérifiez la connexion internet, puis réessayez.</p>
      <button class="btn" onclick="location.reload()">Réessayer</button></div>`;
    return;
  }
  const gardee = await cleGardee("lire");
  if (gardee && gardee.sel === ETAT.infos.sel && gardee.cle) {
    try {
      await ouvrirLivre(gardee.cle);
      lancer();
      return;
    } catch (e) { /* mot de passe changé, ou fichier illisible : on redemande */ }
  }
  ecranConnexion();
}

function ecranConnexion(message = "") {
  $app.innerHTML = `
    <div class="connexion">
      <img src="icone-192.png" alt="">
      <h1>Livre de recettes</h1>
      <p>Entrez le mot de passe du livre pour l'ouvrir.</p>
      <form id="form-connexion" autocomplete="on">
        <div class="champ-mdp">
          <input class="champ" id="mdp" type="password" autocomplete="current-password" placeholder="Mot de passe"
                 autocapitalize="off" autocorrect="off" spellcheck="false" required>
          <button type="button" class="voir-mdp" id="voir-mdp" aria-label="Afficher le mot de passe" title="Afficher le mot de passe">👁️</button>
        </div>
        <label class="case"><input type="checkbox" id="garder" checked> Rester connecté sur cet appareil</label>
        <button class="btn plein" type="submit">Ouvrir le livre</button>
        <div class="erreur" id="erreur">${esc(message)}</div>
      </form>
    </div>`;
  const form = document.getElementById("form-connexion");
  document.getElementById("voir-mdp").addEventListener("click", (ev) => {
    const champ = document.getElementById("mdp"), visible = champ.type === "password";
    champ.type = visible ? "text" : "password";
    ev.currentTarget.textContent = visible ? "🙈" : "👁️";
    ev.currentTarget.setAttribute("aria-label", visible ? "Masquer le mot de passe" : "Afficher le mot de passe");
    ev.currentTarget.title = ev.currentTarget.getAttribute("aria-label");
    champ.focus();
  });
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const bouton = form.querySelector("button"), erreur = document.getElementById("erreur");
    bouton.disabled = true; bouton.textContent = "Ouverture…"; erreur.textContent = "";
    try {
      const cle = await deriverCle(document.getElementById("mdp").value, b64(ETAT.infos.sel), ETAT.infos.iterations);
      await ouvrirLivre(cle);
      if (document.getElementById("garder").checked) await cleGardee("ecrire", { cle, sel: ETAT.infos.sel });
      lancer();
    } catch (e) {
      erreur.textContent = e && e.name === "OperationError" ? "Mot de passe incorrect." :
        (typeof DecompressionStream === "undefined" ? "Ce navigateur est trop ancien : mettez-le à jour." : "Mot de passe incorrect.");
      bouton.disabled = false; bouton.textContent = "Ouvrir le livre";
    }
  });
  setTimeout(() => document.getElementById("mdp")?.focus(), 50);
}

function lancer() {
  window.addEventListener("hashchange", afficher);
  afficher();
  verifierMiseAJour();
  document.addEventListener("visibilitychange", () => { if (!document.hidden) verifierMiseAJour(); });
}
async function verifierMiseAJour(manuel) {
  try {
    const infos = await chargerInfos();
    if (infos.version === ETAT.infos.version) { if (manuel) toast("Le livre est déjà à jour."); return; }
    if (infos.sel !== ETAT.infos.sel) { await cleGardee("oublier"); ETAT.infos = infos; ecranConnexion("Le mot de passe du livre a changé."); return; }
    ETAT.infos = infos;
    await ouvrirLivre(ETAT.cle);
    afficher();
    toast(`Livre mis à jour : ${pluriel(ETAT.recettes.length, "recette")}`);
  } catch (e) { if (manuel) toast("Pas de connexion : le livre enregistré sur l'appareil reste disponible."); }
}

/* ---------- Navigation ---------- */
function afficher() {
  const h = location.hash || "#/";
  const [, page, id] = h.split("/");
  arreterVeille();
  if (page === "r" && id) {
    // « #/r/<id>?p=6 » : ouverte depuis le menu de la semaine, pour 6 personnes
    const [rid, p] = id.split("?p=");
    if (p) ETAT.personnes = { id: decodeURIComponent(rid), n: Math.max(1, +p || 1) };
    return pageFiche(decodeURIComponent(rid));
  }
  if (page === "cuisine" && id) return pageCuisine(decodeURIComponent(id));
  if (page === "courses") return pageCourses();
  if (page === "menu") return pageMenu();
  if (page === "reglages") return pageReglages();
  return pageListe();
}
function nav(actif) {
  const n = (LS.lire("courses", { recettes: [] }).recettes || []).length;
  const lien = (href, ico, lib, cle) =>
    `<a href="${href}" class="${actif === cle ? "actif" : ""}"><span class="ico">${ico}</span>${lib}${cle === "courses" && n ? `<span class="badge">${n}</span>` : ""}</a>`;
  return `<nav class="nav">${lien("#/", "📖", "Recettes", "liste")}${lien("#/menu", "📅", "Menu", "menu")}
    ${lien("#/courses", "🛒", "Courses", "courses")}${lien("#/reglages", "⚙️", "Réglages", "reglages")}</nav>`;
}

/* ---------- Liste et recherche ---------- */
function filtrer() {
  const mots = normaliser(ETAT.recherche).split(" ").filter(Boolean);
  const f = ETAT.filtres, favoris = new Set(LS.lire("favoris", []));
  const res = [];
  for (const r of ETAT.recettes) {
    if (ETAT.categorie && r.cat !== ETAT.categorie) continue;
    if (f.favoris && !favoris.has(r.id)) continue;
    if (f.temps && !(r.total && r.total <= f.temps)) continue;
    if (f.note && r.note < f.note) continue;
    if (f.tags.length && !f.tags.every((t) => r._tags.includes(normaliser(t)))) continue;
    let score = 0;
    if (mots.length) {
      const dansNom = mots.every((m) => r.cle.includes(m));
      const dansIng = mots.every((m) => r.cle.includes(m) || r._ing.includes(m) || r._tags.some((t) => t.includes(m)));
      if (!dansNom && !dansIng) continue;
      score = dansNom ? (r.cle.startsWith(mots[0]) ? 0 : 1) : 2;
    }
    res.push([score, r]);
  }
  res.sort((a, b) => a[0] - b[0]);
  return res.map((x) => x[1]);
}
function nbFiltres() {
  const f = ETAT.filtres;
  return (f.favoris ? 1 : 0) + (f.temps ? 1 : 0) + (f.note ? 1 : 0) + f.tags.length;
}
function carte(r, favoris, choisie) {
  const initiale = esc((r.nom || "?").trim().charAt(0).toUpperCase());
  const details = [r.cat && esc(r.cat), r.total && "⏱ " + duree(r.total), r.note && `<span class="etoiles">${etoiles(r.note)}</span>`,
    favoris.has(r.id) && '<span class="coeur">♥</span>'].filter(Boolean).join("<span>·</span>");
  return `<a class="carte${choisie ? " choisie" : ""}" href="#/r/${encodeURIComponent(r.id)}">
    <div class="vignette" ${r.photo ? `data-photo="${r.photo.p}"` : ""}>${initiale}</div>
    <div class="infos"><div class="nom">${esc(r.nom)}</div><div class="details">${details}</div></div></a>`;
}
function htmlListe(choisie) {
  const cats = [...new Set(ETAT.recettes.map((r) => r.cat).filter(Boolean))];
  const ordre = ["Apéritif", "Entrée", "Plat principal", "Accompagnement", "Dessert", "Petit déjeuner", "En-cas", "Sauce", "Boisson"];
  cats.sort((a, b) => (ordre.indexOf(a) + 1 || 99) - (ordre.indexOf(b) + 1 || 99));
  const n = nbFiltres();
  return `
    <header class="entete">
      <div class="entete-ligne"><h1>📖 Mes recettes</h1>
        <button class="icone-btn" id="btn-filtres" aria-label="Filtres">⚙︎${n ? `<span class="badge" style="right:2px">${n}</span>` : ""}</button></div>
      <div class="recherche"><span class="loupe">🔎</span>
        <input id="recherche" type="search" placeholder="Nom, ingrédient, étiquette…" value="${esc(ETAT.recherche)}" autocomplete="off" enterkeyhint="search">
        <button class="icone-btn effacer" id="effacer" aria-label="Effacer" ${ETAT.recherche ? "" : "hidden"}>✕</button></div>
      <div class="puces" id="puces-cat">
        <button class="puce ${ETAT.categorie ? "" : "active"}" data-cat="">Toutes</button>
        ${cats.map((c) => `<button class="puce ${ETAT.categorie === c ? "active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`).join("")}
      </div>
    </header>
    <div class="compte" id="compte"></div>
    <div class="contenu"><div class="liste" id="liste"></div></div>`;
}
function remplirListe(choisie) {
  const res = filtrer(), favoris = new Set(LS.lire("favoris", []));
  const liste = document.getElementById("liste");
  document.getElementById("compte").textContent = res.length === ETAT.recettes.length ? pluriel(res.length, "recette") :
    `${pluriel(res.length, "recette")} sur ${ETAT.recettes.length}`;
  liste.innerHTML = res.length ? res.map((r) => carte(r, favoris, r.id === choisie)).join("") :
    `<div class="vide"><span class="grand">🥄</span>Aucune recette ne correspond.<br><br>
     <button class="btn secondaire petit" id="tout-afficher">Tout afficher</button></div>`;
  document.getElementById("tout-afficher")?.addEventListener("click", () => {
    ETAT.recherche = ""; ETAT.categorie = ""; ETAT.filtres = { favoris: false, temps: 0, note: 0, tags: [] }; afficher();
  });
  chargerVignettes(liste);
}
function brancherListe(choisie) {
  const champ = document.getElementById("recherche"), effacer = document.getElementById("effacer");
  champ.addEventListener("input", () => { ETAT.recherche = champ.value; effacer.hidden = !champ.value; remplirListe(choisie); });
  champ.addEventListener("keydown", (e) => { if (e.key === "Enter") champ.blur(); });
  effacer.addEventListener("click", () => { ETAT.recherche = ""; champ.value = ""; effacer.hidden = true; remplirListe(choisie); champ.focus(); });
  document.getElementById("puces-cat").addEventListener("click", (e) => {
    const b = e.target.closest(".puce"); if (!b) return;
    ETAT.categorie = b.dataset.cat;
    document.querySelectorAll("#puces-cat .puce").forEach((p) => p.classList.toggle("active", p === b));
    remplirListe(choisie);
  });
  document.getElementById("btn-filtres").addEventListener("click", feuilleFiltres);
  remplirListe(choisie);
}
function pageListe() {
  if (estLarge()) return pageDouble(null);
  $app.innerHTML = `<div class="ecran">${htmlListe()}</div>${nav("liste")}`;
  brancherListe();
  window.scrollTo(0, ETAT.defilementListe || 0);
}
function feuilleFiltres() {
  const f = ETAT.filtres;
  const tags = [...new Set(ETAT.recettes.flatMap((r) => r.tags || []))].sort((a, b) => a.localeCompare(b, "fr"));
  const voile = document.createElement("div");
  voile.className = "voile";
  const puces = (liste, actif, cle) => liste.map(([v, lib]) => `<button class="puce ${actif === v ? "active" : ""}" data-${cle}="${v}">${lib}</button>`).join("");
  voile.innerHTML = `<div class="feuille" role="dialog" aria-label="Filtres"><div class="poignee"></div><h2>Filtres</h2>
    <h3>Mes favoris</h3><div class="puces"><button class="puce ${f.favoris ? "active" : ""}" data-fav="1">♥ Seulement mes favoris</button></div>
    <h3>Temps total</h3><div class="puces">${puces([[0, "Tous"], [15, "≤ 15 min"], [30, "≤ 30 min"], [45, "≤ 45 min"], [60, "≤ 1 h"], [120, "≤ 2 h"]], f.temps, "temps")}</div>
    <h3>Note</h3><div class="puces">${puces([[0, "Toutes"], [3, "★★★ et +"], [4, "★★★★ et +"], [5, "★★★★★"]], f.note, "note")}</div>
    ${tags.length ? `<h3>Étiquettes</h3><div class="puces">${tags.map((t) => `<button class="puce ${f.tags.includes(t) ? "active" : ""}" data-tag="${esc(t)}">#${esc(t)}</button>`).join("")}</div>` : ""}
    <div class="boutons"><button class="btn secondaire" id="f-effacer">Effacer</button><button class="btn" id="f-ok">Voir les recettes</button></div></div>`;
  document.body.appendChild(voile);
  const fermer = () => { voile.remove(); afficher(); };
  voile.addEventListener("click", (e) => {
    if (e.target === voile) return fermer();
    const b = e.target.closest(".puce");
    if (b) {
      if (b.dataset.fav) f.favoris = !f.favoris;
      if (b.dataset.temps !== undefined) f.temps = +b.dataset.temps;
      if (b.dataset.note !== undefined) f.note = +b.dataset.note;
      if (b.dataset.tag !== undefined) f.tags = f.tags.includes(b.dataset.tag) ? f.tags.filter((t) => t !== b.dataset.tag) : [...f.tags, b.dataset.tag];
      const groupe = b.parentElement;
      if (b.dataset.temps !== undefined || b.dataset.note !== undefined) groupe.querySelectorAll(".puce").forEach((p) => p.classList.toggle("active", p === b));
      else b.classList.toggle("active");
    }
    if (e.target.id === "f-effacer") { ETAT.filtres = { favoris: false, temps: 0, note: 0, tags: [] }; fermer(); }
    if (e.target.id === "f-ok") fermer();
  });
}

/* ---------- Fiche d'une recette ---------- */
const estLarge = () => window.matchMedia("(min-width: 960px)").matches;
window.addEventListener("resize", () => {
  const large = estLarge();
  if (large !== estLarge._avant && ETAT.recettes.length && !document.querySelector(".cuisine")) { estLarge._avant = large; afficher(); }
});
estLarge._avant = estLarge();

function personnesDe(r) { return (ETAT.personnes && ETAT.personnes.id === r.id) ? ETAT.personnes.n : r.pers; }
function htmlFiche(r) {
  const favoris = new Set(LS.lire("favoris", []));
  const pers = personnesDe(r), facteur = r.pers ? frac(pers, r.pers) : [1, 1];
  const modifie = facteur[0] !== facteur[1];
  const tags = [r.cat && `<span class="etiquette">${esc(r.cat)}</span>`, ...(r.tags || []).map((t) => `<span class="etiquette neutre">#${esc(t)}</span>`)].filter(Boolean).join("");
  const infos = [r.tempsTexte && "⏱ " + esc(r.tempsTexte), !r.tempsTexte && r.total && "⏱ " + duree(r.total), r.note && `<span class="etoiles">${etoiles(r.note)}</span>`,
    ...(r.infos || []).filter((i) => !/temps|pr[ée]paration|cuisson|repos/i.test(i)).map(esc)].filter(Boolean);
  let n = 0;
  const etapes = r.etapes.map((e) => {
    const partie = e.t ? `<li class="partie">${esc(e.t)}</li>` : "";
    n += 1;
    const chronos = e.min.length ? `<div class="chrono">${e.min.map(([l, s]) => `<button data-chrono="${s}" data-lib="${esc(`Étape ${n} · ${l}`)}">⏱ ${esc(l)}</button>`).join("")}</div>` : "";
    return `${partie}<li class="etape"><span class="num">${n}</span><div class="texte">${esc(e.x)}${chronos}</div></li>`;
  }).join("");
  return `
    <div class="fiche">
      <div class="barre-fiche" id="barre-fiche">
        <button class="icone-btn" id="retour" aria-label="Retour">←</button>
        <span class="titre-court">${esc(r.nom)}</span>
        <button class="icone-btn" id="favori" aria-label="Favori">${favoris.has(r.id) ? '<span class="coeur">♥</span>' : "♡"}</button>
        <button class="icone-btn" id="partager" aria-label="Partager">⤴</button>
      </div>
      ${r.photo ? `<div class="photo-fiche" id="photo-fiche"></div>` : ""}
      <div class="corps-fiche">
        <h1>${esc(r.nom)}</h1>
        <div class="etiquettes">${tags}</div>
        ${infos.length ? `<div class="ligne-infos">${infos.map((i) => `<span>${i}</span>`).join("")}</div>` : ""}
        ${r.pers ? `<div class="personnes"><span>👥 Pour <b>${pers}</b> ${pers > 1 ? "personnes" : "personne"}</span>
          <div class="compteur"><button id="moins" aria-label="Moins">−</button><output>${pers}</output><button id="plus" aria-label="Plus">+</button></div></div>`
          : (r.persTexte ? `<div class="ligne-infos">👥 ${esc(r.persTexte)}</div>` : "")}
        ${r.com ? `<div class="note-perso">📝 ${esc(r.com)}</div>` : ""}
        ${r.ing.length ? `<section class="section"><h2>Ingrédients ${modifie ? "<small>quantités recalculées</small>" : ""}</h2>
          <ul class="ingredients">${r.ing.map((i) => {
            const q = quantite(i, facteur);
            return `<li><label><input type="checkbox"><span class="nom-ing">${esc(i.n)}</span><span class="qte ${modifie && q !== i.q ? "modifiee" : ""}">${esc(q)}</span></label></li>`;
          }).join("")}</ul></section>` : ""}
        ${r.etapes.length ? `<section class="section"><h2>Préparation</h2><ol class="etapes">${etapes}</ol></section>` : ""}
      </div>
      <div class="actions-fiche">
        ${r.etapes.length ? `<button class="btn" id="cuisiner">👩‍🍳 Mode cuisine</button>` : ""}
        <button class="btn secondaire" id="aux-courses">🛒 Courses</button>
      </div>
    </div>`;
}
function brancherFiche(r, conteneur) {
  const q = (s) => conteneur.querySelector(s);
  if (r.photo) photo(r.photo.g).then((url) => { const el = q("#photo-fiche"); if (url && el) el.style.backgroundImage = `url(${url})`; });
  q("#retour").addEventListener("click", () => { if (history.length > 1 && ETAT.venuDeLaListe) history.back(); else location.hash = "#/"; });
  q("#favori").addEventListener("click", () => {
    const f = new Set(LS.lire("favoris", []));
    if (f.has(r.id)) { f.delete(r.id); toast("Retirée des favoris"); } else { f.add(r.id); toast("Ajoutée aux favoris ♥"); }
    LS.ecrire("favoris", [...f]);
    q("#favori").innerHTML = f.has(r.id) ? '<span class="coeur">♥</span>' : "♡";
  });
  q("#partager").addEventListener("click", () => partager(r.nom, textePartage(r)));
  const changer = (d) => {
    const n = Math.max(1, Math.min(99, personnesDe(r) + d));
    ETAT.personnes = { id: r.id, n };
    const y = (conteneur.closest(".volet-fiche") || document.scrollingElement).scrollTop;
    conteneur.innerHTML = htmlFiche(r); brancherFiche(r, conteneur);
    (conteneur.closest(".volet-fiche") || document.scrollingElement).scrollTop = y;
  };
  q("#moins")?.addEventListener("click", () => changer(-1));
  q("#plus")?.addEventListener("click", () => changer(+1));
  q("#cuisiner")?.addEventListener("click", () => { location.hash = `#/cuisine/${encodeURIComponent(r.id)}`; });
  q("#aux-courses").addEventListener("click", () => {
    const c = LS.lire("courses", { recettes: [], coches: {}, libres: [] });
    const p = personnesDe(r) || null, existe = c.recettes.find((x) => x.id === r.id);
    if (existe) existe.pers = p; else c.recettes.push({ id: r.id, pers: p });
    LS.ecrire("courses", c);
    toast(existe ? "Liste de courses mise à jour" : "Ajoutée à la liste de courses 🛒");
    const badge = document.querySelector('.nav a[href="#/courses"]');
    if (badge) badge.outerHTML = nav("").match(/<a href="#\/courses"[\s\S]*?<\/a>/)[0];
  });
  conteneur.querySelectorAll("[data-chrono]").forEach((b) => b.addEventListener("click", () => lancerMinuteur(b.dataset.lib, +b.dataset.chrono)));
  const barre = q("#barre-fiche"), defileur = conteneur.closest(".volet-fiche") || window;
  const suivre = () => barre.classList.toggle("defile", ((defileur.scrollY ?? defileur.scrollTop) || 0) > 120);
  defileur.addEventListener("scroll", suivre, { passive: true });
}
function pageFiche(id) {
  const r = ETAT.parId.get(id);
  if (!r) { location.hash = "#/"; return; }
  if (estLarge()) return pageDouble(r);
  ETAT.venuDeLaListe = true;
  $app.innerHTML = `<div id="fiche"></div>`;
  const c = document.getElementById("fiche");
  c.innerHTML = htmlFiche(r); brancherFiche(r, c);
  window.scrollTo(0, 0);
}
function pageDouble(r) {
  let double = document.querySelector(".double");
  if (!double) {
    $app.innerHTML = `<div class="double"><div class="volet-liste"><div class="ecran">${htmlListe(r && r.id)}</div></div>
      <div class="volet-fiche" id="volet-fiche"></div></div>${nav("liste")}`;
    brancherListe(r && r.id);
    double = document.querySelector(".double");
  } else {
    double.querySelectorAll(".carte").forEach((c) => c.classList.toggle("choisie", r && c.getAttribute("href") === `#/r/${encodeURIComponent(r.id)}`));
  }
  const v = document.getElementById("volet-fiche");
  if (!r) { v.innerHTML = `<div class="vide" style="padding-top:30vh"><span class="grand">📖</span>Choisissez une recette dans la liste.</div>`; return; }
  ETAT.venuDeLaListe = false;
  v.innerHTML = htmlFiche(r); brancherFiche(r, v); v.scrollTop = 0;
}

/* ---------- Partage ---------- */
function textePartage(r) {
  const pers = personnesDe(r), facteur = r.pers ? frac(pers, r.pers) : [1, 1];
  const l = [`🍽️ ${r.nom}`];
  const d = [];
  if (pers || r.persTexte) d.push(`👥 Pour ${pers || r.persTexte} personne${(pers || 2) > 1 ? "s" : ""}`);
  if (r.tempsTexte) d.push(`⏱️ ${r.tempsTexte}`);
  if (d.length) l.push(d.join(" · "));
  l.push("", "🛒 Ingrédients :");
  r.ing.forEach((i) => { const q = quantite(i, facteur); l.push(`• ${i.n}${q ? " : " + q : ""}`); });
  if (r.etapes.length) {
    l.push("", "👩‍🍳 Préparation :");
    r.etapes.forEach((e, k) => { if (e.t) l.push(`— ${e.t} —`); l.push(`${k + 1}. ${e.x}`); });
  }
  return l.join("\n");
}
async function partager(titre, texte) {
  if (navigator.share) {
    try { await navigator.share({ title: titre, text: texte }); return; } catch (e) { if (e.name === "AbortError") return; }
  }
  try { await navigator.clipboard.writeText(texte); toast("Texte copié : collez-le dans WhatsApp, Messenger, un SMS…"); }
  catch (e) { location.href = "https://api.whatsapp.com/send?text=" + encodeURIComponent(texte.slice(0, 1800)); }
}

/* ---------- Minuteurs (continuent pendant la navigation) ---------- */
const MINUTEURS = [];
let audio = null;
function debloquerSon() {
  try { audio = audio || new (window.AudioContext || window.webkitAudioContext)(); if (audio.state === "suspended") audio.resume(); } catch (e) { audio = null; }
}
function bip() {
  if (!audio) return;
  const t = audio.currentTime;
  [0, 0.25, 0.5].forEach((d) => {
    const o = audio.createOscillator(), g = audio.createGain();
    o.type = "sine"; o.frequency.value = 880; o.connect(g); g.connect(audio.destination);
    g.gain.setValueAtTime(0.0001, t + d); g.gain.exponentialRampToValueAtTime(0.4, t + d + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, t + d + 0.2); o.start(t + d); o.stop(t + d + 0.22);
  });
}
function lancerMinuteur(libelle, secondes) {
  debloquerSon();
  MINUTEURS.push({ id: Date.now() + Math.random(), libelle, fin: Date.now() + secondes * 1000, pause: null, sonne: false });
  toast(`Minuteur lancé : ${libelle.split("· ").pop()}`);
  dessinerMinuteurs();
  if (!lancerMinuteur._t) lancerMinuteur._t = setInterval(tic, 500);
}
function formatChrono(s) { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60; return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(x).padStart(2, "0"); }
function tic() {
  for (const m of MINUTEURS) {
    if (!m.pause && !m.sonne && Date.now() >= m.fin) { m.sonne = true; if (navigator.vibrate) navigator.vibrate([400, 200, 400, 200, 400]); }
  }
  if (MINUTEURS.some((m) => m.sonne) && (tic.n = (tic.n || 0) + 1) % 3 === 0) bip();
  if (!MINUTEURS.length) { clearInterval(lancerMinuteur._t); lancerMinuteur._t = null; }
  dessinerMinuteurs();
}
function dessinerMinuteurs() {
  const zone = document.getElementById("minuteurs");
  zone.hidden = !MINUTEURS.length;
  zone.style.bottom = document.querySelector(".actions-fiche, .cuisine-bas") ? "calc(140px + var(--bas-sur))" : "";
  const temps = (m) => m.sonne ? "⏰ Terminé !" : formatChrono(m.pause ? Math.round(m.reste / 1000) : Math.max(0, Math.round((m.fin - Date.now()) / 1000)));
  // On ne reconstruit les minuteurs que si leur état change : sinon seuls les chiffres bougent (les boutons restent cliquables)
  const signature = MINUTEURS.map((m) => `${m.id}:${m.sonne}:${!!m.pause}`).join("|");
  if (signature !== zone.dataset.signature) {
    zone.dataset.signature = signature;
    zone.innerHTML = MINUTEURS.map((m) => `<div class="minuteur ${m.sonne ? "sonne" : ""}" data-id="${m.id}">
      <div><div class="temps">${temps(m)}</div><small>${esc(m.libelle)}</small></div>
      ${m.sonne ? "" : `<button data-action="pause" aria-label="Pause">${m.pause ? "▶" : "⏸"}</button>`}
      <button data-action="stop" aria-label="Arrêter">✕</button></div>`).join("");
    return;
  }
  MINUTEURS.forEach((m, k) => { const el = zone.children[k]?.querySelector(".temps"); if (el) el.textContent = temps(m); });
}
document.getElementById("minuteurs").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  const id = +b.closest(".minuteur").dataset.id, m = MINUTEURS.find((x) => x.id === id); if (!m) return;
  if (b.dataset.action === "stop") MINUTEURS.splice(MINUTEURS.indexOf(m), 1);
  else if (m.pause) { m.fin = Date.now() + m.reste; m.pause = null; }
  else { m.reste = m.fin - Date.now(); m.pause = Date.now(); }
  dessinerMinuteurs();
});

/* ---------- Mode cuisine ---------- */
let verrou = null;
async function garderEcranAllume() {
  try { if ("wakeLock" in navigator) { verrou = await navigator.wakeLock.request("screen"); } } catch (e) { verrou = null; }
}
function arreterVeille() { if (verrou) { verrou.release().catch(() => {}); verrou = null; } }
document.addEventListener("visibilitychange", () => { if (!document.hidden && document.querySelector(".cuisine")) garderEcranAllume(); });

function pageCuisine(id) {
  const r = ETAT.parId.get(id);
  if (!r) { location.hash = "#/"; return; }
  const pers = personnesDe(r), facteur = r.pers ? frac(pers, r.pers) : [1, 1];
  // Étape 0 : les ingrédients à préparer
  const pages = [{ ingredients: true }, ...r.etapes.map((e, k) => ({ ...e, n: k + 1 }))];
  let i = ETAT.cuisine && ETAT.cuisine.id === id ? ETAT.cuisine.i : 0;
  const taille = LS.lire("tailleCuisine", 1.55);
  $app.innerHTML = `
    <div class="cuisine">
      <div class="cuisine-haut">
        <button class="icone-btn" id="quitter" aria-label="Quitter">✕</button>
        <div class="titre">${esc(r.nom)}</div>
        <button class="icone-btn" id="plus-petit" aria-label="Texte plus petit">A−</button>
        <button class="icone-btn" id="plus-grand" aria-label="Texte plus grand">A+</button>
      </div>
      <div class="progression"><div id="barre"></div></div>
      <div class="cuisine-num" id="num"></div>
      <div class="cuisine-partie" id="partie"></div>
      <div class="cuisine-etape" id="etape"></div>
      <div class="chrono" id="chronos"></div>
      <div class="cuisine-bas">
        <button class="btn secondaire" id="prec">◀ Précédente</button>
        <button class="btn" id="suiv">Suivante ▶</button>
      </div>
    </div>`;
  const zone = document.getElementById("etape");
  zone.style.fontSize = taille + "em";
  const coches = new Set();
  const montrer = () => {
    ETAT.cuisine = { id, i };
    const p = pages[i];
    document.getElementById("barre").style.width = `${(i / (pages.length - 1 || 1)) * 100}%`;
    document.getElementById("num").textContent = p.ingredients ? `Ingrédients · pour ${pers || r.persTexte || "?"} pers.` : `Étape ${p.n} / ${r.etapes.length}`;
    const partie = p.ingredients ? "" : (p.t || [...r.etapes.slice(0, p.n)].reverse().find((e) => e.t)?.t || "");
    document.getElementById("partie").textContent = partie;
    if (p.ingredients) {
      zone.classList.add("ingredients-vue");
      zone.innerHTML = `<ul class="ingredients">${r.ing.map((ing, k) => `<li><label><input type="checkbox" data-k="${k}" ${coches.has(k) ? "checked" : ""}>
        <span class="nom-ing">${esc(ing.n)}</span><span class="qte">${esc(quantite(ing, facteur))}</span></label></li>`).join("")}</ul>`;
      zone.querySelectorAll("input").forEach((c) => c.addEventListener("change", () => { c.checked ? coches.add(+c.dataset.k) : coches.delete(+c.dataset.k); }));
    } else {
      zone.classList.remove("ingredients-vue");
      zone.textContent = p.x;
    }
    zone.scrollTop = 0;
    document.getElementById("chronos").innerHTML = (p.min || []).map(([l, s]) => `<button data-s="${s}" data-l="${esc(`Étape ${p.n} · ${l}`)}">⏱ Lancer ${esc(l)}</button>`).join("");
    document.getElementById("prec").disabled = i === 0;
    document.getElementById("suiv").textContent = i === pages.length - 1 ? "Terminé ✔" : (i === 0 ? "C'est parti ▶" : "Suivante ▶");
  };
  const aller = (d) => {
    if (i + d >= pages.length) { ETAT.cuisine = null; quitter(); toast("Bon appétit ! 😋"); return; }
    i = Math.max(0, i + d); montrer();
  };
  const quitter = () => { arreterVeille(); if (ETAT.venuDeLaListe !== undefined) history.back(); else location.hash = `#/r/${encodeURIComponent(id)}`; };
  document.getElementById("quitter").addEventListener("click", quitter);
  document.getElementById("prec").addEventListener("click", () => aller(-1));
  document.getElementById("suiv").addEventListener("click", () => aller(+1));
  document.getElementById("chronos").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) lancerMinuteur(b.dataset.l, +b.dataset.s); });
  const tailler = (d) => { const t = Math.max(1, Math.min(3, (LS.lire("tailleCuisine", 1.55) + d))); LS.ecrire("tailleCuisine", t); zone.style.fontSize = t + "em"; };
  document.getElementById("plus-petit").addEventListener("click", () => tailler(-0.15));
  document.getElementById("plus-grand").addEventListener("click", () => tailler(+0.15));
  // Glisser à gauche / à droite pour changer d'étape
  let x0 = null, y0 = null;
  zone.addEventListener("touchstart", (e) => { x0 = e.touches[0].clientX; y0 = e.touches[0].clientY; }, { passive: true });
  zone.addEventListener("touchend", (e) => {
    if (x0 === null) return;
    const dx = e.changedTouches[0].clientX - x0, dy = e.changedTouches[0].clientY - y0;
    if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) aller(dx < 0 ? +1 : -1);
    x0 = null;
  });
  document.onkeydown = (e) => {
    if (!document.querySelector(".cuisine")) { document.onkeydown = null; return; }
    if (e.key === "ArrowRight" || e.key === " ") { e.preventDefault(); aller(+1); }
    if (e.key === "ArrowLeft") aller(-1);
    if (e.key === "Escape") quitter();
  };
  debloquerSon();
  garderEcranAllume();
  montrer();
  dessinerMinuteurs();
}

/* ---------- Liste de courses ---------- */
function calculerCourses(c) {
  const groupes = new Map();
  for (const sel of c.recettes) {
    const r = ETAT.parId.get(sel.id); if (!r) continue;
    const facteur = r.pers && sel.pers ? frac(sel.pers, r.pers) : [1, 1];
    for (const ing of r.ing) {
      if (!groupes.has(ing.k)) groupes.set(ing.k, { nom: ing.n, totaux: new Map(), autres: [], recettes: [] });
      const g = groupes.get(ing.k);
      if (!g.recettes.includes(r.nom)) g.recettes.push(r.nom);
      if (ing.c) {
        const v = fmul(arrondi(fmul(ing.c.v, facteur)), ing.c.x);
        const t = g.totaux.get(ing.c.b);
        g.totaux.set(ing.c.b, { v: t ? fadd(t.v, v) : v, u: t ? t.u : ing.c.u });
      } else {
        const q = quantite(ing, facteur);
        if (q && !g.autres.includes(q)) g.autres.push(q);
      }
    }
  }
  return [...groupes.entries()].map(([k, g]) => ({
    k, nom: g.nom, recettes: g.recettes,
    qte: [...[...g.totaux.values()].map((t) => formaterTotal(t.v, t.u)), ...g.autres].join(" + "),
  })).sort((a, b) => normaliser(a.nom).localeCompare(normaliser(b.nom), "fr"));
}
function pageCourses() {
  const c = LS.lire("courses", { recettes: [], coches: {}, libres: [] });
  c.coches = c.coches || {}; c.libres = c.libres || [];
  c.recettes = c.recettes.filter((x) => ETAT.parId.has(x.id));
  const articles = calculerCourses(c);
  const ligneArticle = (a) => `<label class="ligne ${c.coches[a.k] ? "cochee" : ""}"><input type="checkbox" data-k="${esc(a.k)}" ${c.coches[a.k] ? "checked" : ""}>
    <span class="lib">${esc(a.nom)}<small>${esc(a.recettes.join(", "))}</small></span><span class="qte">${esc(a.qte)}</span></label>`;
  const aFaire = articles.filter((a) => !c.coches[a.k]), faits = articles.filter((a) => c.coches[a.k]);
  $app.innerHTML = `
    <div class="ecran">
      <header class="entete"><div class="entete-ligne"><h1>🛒 Liste de courses</h1>
        ${articles.length || c.libres.length ? `<button class="icone-btn" id="partager-liste" aria-label="Partager">⤴</button>` : ""}</div></header>
      <div class="contenu">
        ${c.recettes.length ? `<div class="bloc"><div class="bloc-titre">Recettes (${c.recettes.length})</div>
          ${c.recettes.map((x) => { const r = ETAT.parId.get(x.id); return `<div class="ligne"><a class="lib" href="#/r/${encodeURIComponent(r.id)}" style="color:inherit;text-decoration:none">${esc(r.nom)}</a>
            ${x.pers ? `<div class="compteur"><button data-moins="${esc(r.id)}">−</button><output>${x.pers}</output><button data-plus="${esc(r.id)}">+</button></div>` : ""}
            <button class="icone-btn" data-retirer="${esc(r.id)}" aria-label="Retirer">✕</button></div>`; }).join("")}</div>`
          : `<div class="vide"><span class="grand">🧺</span>Votre liste est vide.<br>Ouvrez une recette et touchez <b>🛒 Courses</b>,<br>ou ajoutez le menu de la semaine.</div>`}
        <div class="bloc"><div class="bloc-titre">À acheter${aFaire.length ? ` (${aFaire.length})` : ""}</div>
          ${aFaire.map(ligneArticle).join("")}
          ${c.libres.map((l, k) => `<label class="ligne ${l.ok ? "cochee" : ""}"><input type="checkbox" data-libre="${k}" ${l.ok ? "checked" : ""}><span class="lib">${esc(l.t)}</span>
            <button class="icone-btn" data-suppr="${k}" aria-label="Supprimer">✕</button></label>`).join("")}
          <form class="ajout" id="ajout"><input id="libre" placeholder="Ajouter un article (pain, lessive…)" enterkeyhint="done"><button class="btn petit">Ajouter</button></form>
        </div>
        ${faits.length ? `<div class="bloc"><div class="bloc-titre">Dans le panier (${faits.length})</div>${faits.map(ligneArticle).join("")}</div>` : ""}
        ${articles.length || c.libres.length ? `<div class="barre-boutons"><button class="btn secondaire petit" id="decocher">Tout décocher</button>
          <button class="btn secondaire petit" id="vider">Vider la liste</button></div>` : ""}
      </div>
    </div>${nav("courses")}`;
  const enregistrer = () => { LS.ecrire("courses", c); pageCourses(); };
  $app.querySelectorAll("input[data-k]").forEach((x) => x.addEventListener("change", () => { if (x.checked) c.coches[x.dataset.k] = 1; else delete c.coches[x.dataset.k]; enregistrer(); }));
  $app.querySelectorAll("input[data-libre]").forEach((x) => x.addEventListener("change", () => { c.libres[+x.dataset.libre].ok = x.checked; enregistrer(); }));
  $app.querySelectorAll("[data-suppr]").forEach((b) => b.addEventListener("click", (e) => { e.preventDefault(); c.libres.splice(+b.dataset.suppr, 1); enregistrer(); }));
  $app.querySelectorAll("[data-retirer]").forEach((b) => b.addEventListener("click", () => { c.recettes = c.recettes.filter((x) => x.id !== b.dataset.retirer); enregistrer(); }));
  $app.querySelectorAll("[data-moins],[data-plus]").forEach((b) => b.addEventListener("click", () => {
    const x = c.recettes.find((y) => y.id === (b.dataset.moins || b.dataset.plus));
    x.pers = Math.max(1, Math.min(99, x.pers + (b.dataset.plus ? 1 : -1))); enregistrer();
  }));
  document.getElementById("ajout").addEventListener("submit", (e) => {
    e.preventDefault(); const t = document.getElementById("libre").value.trim();
    if (t) { c.libres.push({ t, ok: false }); enregistrer(); setTimeout(() => document.getElementById("libre")?.focus(), 30); }
  });
  document.getElementById("decocher")?.addEventListener("click", () => { c.coches = {}; c.libres.forEach((l) => { l.ok = false; }); enregistrer(); });
  document.getElementById("vider")?.addEventListener("click", () => { if (confirm("Vider toute la liste de courses ?")) { LS.ecrire("courses", { recettes: [], coches: {}, libres: [] }); pageCourses(); } });
  document.getElementById("partager-liste")?.addEventListener("click", () => {
    const lignes = ["🛒 Liste de courses", ""];
    aFaire.forEach((a) => lignes.push(`☐ ${a.nom}${a.qte ? " : " + a.qte : ""}`));
    c.libres.filter((l) => !l.ok).forEach((l) => lignes.push(`☐ ${l.t}`));
    partager("Liste de courses", lignes.join("\n"));
  });
}

/* ---------- Menu de la semaine (préparé sur le PC) ---------- */
const JOURS = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"];
const MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
function lundiDe(d) { const x = new Date(d.getFullYear(), d.getMonth(), d.getDate()); x.setDate(x.getDate() - ((x.getDay() + 6) % 7)); return x; }
function pageMenu() {
  const decalage = ETAT.semaine || 0;
  const lundi = lundiDe(new Date()); lundi.setDate(lundi.getDate() + 7 * decalage);
  const planning = (ETAT.livre && ETAT.livre.planning) || {};
  const jours = [...Array(7)].map((_, k) => { const d = new Date(lundi); d.setDate(d.getDate() + k); return d; });
  const auj = iso(new Date());
  const plats = [];
  const htmlJours = jours.map((d, k) => {
    const p = planning[iso(d)] || {};
    const repas = [["midi", "Midi"], ["soir", "Soir"]].map(([cle, lib]) => {
      const liste = (p[cle] || []).filter((x) => ETAT.parId.has(x.id));
      liste.forEach((x) => plats.push(x));
      return `<div class="repas"><span class="moment">${lib}</span><div class="plats">${liste.length ? liste.map((x) =>
        `<a href="#/r/${encodeURIComponent(x.id)}${ETAT.parId.get(x.id).pers ? `?p=${+x.personnes || 1}` : ""}">${esc(ETAT.parId.get(x.id).nom)} <small style="color:var(--texte-doux);font-weight:400">· ${x.personnes} pers.</small></a>`).join("")
        : '<span class="rien">—</span>'}</div></div>`;
    }).join("");
    return `<div class="jour ${iso(d) === auj ? "aujourdhui" : ""}"><h3>${JOURS[k]} ${d.getDate()} ${MOIS[d.getMonth()]}${iso(d) === auj ? "<small>Aujourd'hui</small>" : ""}</h3>${repas}</div>`;
  }).join("");
  const fin = jours[6];
  $app.innerHTML = `
    <div class="ecran">
      <header class="entete"><div class="entete-ligne"><h1>📅 Menu de la semaine</h1></div></header>
      <div class="contenu">
        <div class="semaine-nav"><button class="icone-btn" id="sem-prec" aria-label="Semaine précédente">◀</button>
          <strong>Du ${lundi.getDate()} ${MOIS[lundi.getMonth()]} au ${fin.getDate()} ${MOIS[fin.getMonth()]}</strong>
          <button class="icone-btn" id="sem-suiv" aria-label="Semaine suivante">▶</button></div>
        ${decalage ? `<p style="text-align:center;margin:-4px 0 10px"><button class="btn secondaire petit" id="sem-auj">Revenir à cette semaine</button></p>` : ""}
        ${htmlJours}
        ${plats.length ? `<button class="btn plein" id="sem-courses">🛒 Ajouter la semaine aux courses</button>` :
          `<p class="vide" style="padding:10px">Le menu de cette semaine n'a pas encore été préparé sur le PC.</p>`}
      </div>
    </div>${nav("menu")}`;
  document.getElementById("sem-prec").addEventListener("click", () => { ETAT.semaine = decalage - 1; pageMenu(); });
  document.getElementById("sem-suiv").addEventListener("click", () => { ETAT.semaine = decalage + 1; pageMenu(); });
  document.getElementById("sem-auj")?.addEventListener("click", () => { ETAT.semaine = 0; pageMenu(); });
  document.getElementById("sem-courses")?.addEventListener("click", () => {
    const c = LS.lire("courses", { recettes: [], coches: {}, libres: [] });
    const total = new Map();
    plats.forEach((x) => total.set(x.id, (total.get(x.id) || 0) + (+x.personnes || 1)));
    total.forEach((pers, id) => {
      const r = ETAT.parId.get(id), e = c.recettes.find((y) => y.id === id);
      const p = r.pers ? pers : null;
      if (e) e.pers = p; else c.recettes.push({ id, pers: p });
    });
    LS.ecrire("courses", c);
    location.hash = "#/courses";
    toast(`${pluriel(total.size, "recette")} ajoutée${total.size > 1 ? "s" : ""} aux courses`);
  });
}

/* ---------- Réglages ---------- */
function appliquerReglages() {
  document.documentElement.style.setProperty("--taille", LS.lire("taille", 16) + "px");
  const theme = LS.lire("theme", "auto");
  if (theme === "auto") document.documentElement.removeAttribute("data-theme"); else document.documentElement.dataset.theme = theme;
}
window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); ETAT.installation = e; });
const estInstallee = () => window.matchMedia("(display-mode: standalone)").matches || navigator.standalone;
const estIOS = () => /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
function pageReglages() {
  const date = ETAT.livre && ETAT.livre.date ? new Date(ETAT.livre.date) : null;
  const taille = LS.lire("taille", 16), theme = LS.lire("theme", "auto");
  let installation = "";
  if (!estInstallee()) {
    installation = estIOS()
      ? `<div class="aide-installation">📲 <b>Installer sur l'écran d'accueil</b> : dans Safari, touchez le bouton <b>Partager</b> <span style="font-size:1.1em">⎋</span>, puis <b>Sur l'écran d'accueil</b>.</div>`
      : ETAT.installation ? `<div class="reglage"><span>📲 Installer l'application<small>Une icône sur l'écran d'accueil, comme une vraie appli</small></span><button class="btn petit" id="installer">Installer</button></div>`
      : `<div class="aide-installation">📲 <b>Installer sur l'écran d'accueil</b> : ouvrez le menu du navigateur <b>⋮</b>, puis <b>Installer l'application</b> ou <b>Ajouter à l'écran d'accueil</b>.</div>`;
  }
  $app.innerHTML = `
    <div class="ecran">
      <header class="entete"><div class="entete-ligne"><h1>⚙️ Réglages</h1></div></header>
      <div class="contenu">
        <div class="bloc"><div class="bloc-titre">Le livre</div>
          <div class="reglage"><span>📖 ${pluriel(ETAT.recettes.length, "recette")}<small>${date ? `Mis à jour le ${date.getDate()} ${MOIS[date.getMonth()]} ${date.getFullYear()} à ${date.getHours()} h ${String(date.getMinutes()).padStart(2, "0")}` : ""}</small></span>
            <button class="btn secondaire petit" id="actualiser">Actualiser</button></div>
          ${installation}
        </div>
        <div class="bloc"><div class="bloc-titre">Affichage</div>
          <div class="reglage"><span>Taille du texte</span><div class="compteur"><button id="t-moins" aria-label="Plus petit">A−</button><output>${Math.round(taille / 16 * 100)} %</output><button id="t-plus" aria-label="Plus grand">A+</button></div></div>
          <div class="reglage"><span>Thème</span><div class="puces" style="padding:0">${[["auto", "Auto"], ["light", "Clair"], ["dark", "Sombre"]].map(([v, l]) =>
            `<button class="puce ${theme === v ? "active" : ""}" data-theme="${v}">${l}</button>`).join("")}</div></div>
        </div>
        <div class="bloc"><div class="bloc-titre">Sécurité</div>
          <div class="reglage"><span>🔒 Recettes chiffrées<small>Le livre ne s'ouvre qu'avec son mot de passe. Vos favoris et votre liste de courses restent sur cet appareil.</small></span></div>
          <div class="reglage"><span>Se déconnecter<small>Le mot de passe sera redemandé</small></span><button class="btn secondaire petit" id="deconnecter">Se déconnecter</button></div>
        </div>
        <p style="text-align:center;color:var(--texte-doux);font-size:.85em">Livre de recettes · application de consultation<br>Les recettes se modifient sur le PC, puis « Publier sur les téléphones ».</p>
      </div>
    </div>${nav("reglages")}`;
  document.getElementById("actualiser").addEventListener("click", () => verifierMiseAJour(true));
  document.getElementById("installer")?.addEventListener("click", async () => { ETAT.installation.prompt(); await ETAT.installation.userChoice; ETAT.installation = null; pageReglages(); });
  const tailler = (d) => { LS.ecrire("taille", Math.max(13, Math.min(24, taille + d))); appliquerReglages(); pageReglages(); };
  document.getElementById("t-moins").addEventListener("click", () => tailler(-1));
  document.getElementById("t-plus").addEventListener("click", () => tailler(+1));
  $app.querySelectorAll("[data-theme]").forEach((b) => b.addEventListener("click", () => { LS.ecrire("theme", b.dataset.theme); appliquerReglages(); pageReglages(); }));
  document.getElementById("deconnecter").addEventListener("click", async () => {
    if (!confirm("Se déconnecter ? Le mot de passe du livre sera redemandé.")) return;
    await cleGardee("oublier"); location.hash = "#/"; location.reload();
  });
}

// Mémorise la position dans la liste avant d'ouvrir une recette
document.addEventListener("click", (e) => { if (e.target.closest(".carte") && !estLarge()) ETAT.defilementListe = window.scrollY; }, true);

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
demarrer();
