// Rygiel: zamek strony pobierania. Ten sam plik dziala w przegladarce (strona) i w Node (wydaj.mjs, testy).
// Uzywa tylko WebCrypto (globalThis.crypto.subtle), bez bibliotek.
//
// Uklad:
//  - zamek.json: opis wydania (wersja, zmiany, adresy czesci, klucz pliku) zaszyfrowany AES-256-GCM
//    kluczem z kodu dostepu (PBKDF2-SHA256, 600 000 powtorzen, losowa sol). Bez kodu to losowe bajty.
//  - plik wydania: dzielony na bloki (domyslnie 4 MiB), kazdy blok szyfrowany AES-256-GCM losowym
//    kluczem pliku. IV = 4 losowe bajty wydania + numer bloku (8 bajtow), AAD = numer bloku + znacznik
//    ostatniego bloku, wiec zamiana kolejnosci, uciecie konca albo zmiana jednego bajtu konczy sie bledem.
//  - zaszyfrowane bloki leza w czesciach (pliki d/<losowa nazwa>.bin), po kilka blokow na czesc.

export const ALFABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // 32 znaki, bez 0 O 1 I
export const DLUGOSC_KODU = 16; // 16 znakow po 5 bitow = 80 bitow
export const POWTORZENIA = 600000;
export const TAG = 16;

const subtle = () => globalThis.crypto.subtle;
const tekst = new TextEncoder();

export class ZlyKod extends Error {
  constructor() { super('zly kod'); this.name = 'ZlyKod'; }
}

export function b64(bajty) {
  let s = '';
  for (const b of new Uint8Array(bajty)) s += String.fromCharCode(b);
  return btoa(s);
}

export function zB64(napis) {
  const s = atob(napis);
  const wynik = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) wynik[i] = s.charCodeAt(i);
  return wynik;
}

// Kod wpisany przez czlowieka: wielkie litery, bez spacji i myslnikow.
export function normalizujKod(wpis) {
  return String(wpis).toUpperCase().replace(/[\s-]/g, '');
}

export function poprawnyKsztalt(kod) {
  if (kod.length !== DLUGOSC_KODU) return false;
  for (const z of kod) if (!ALFABET.includes(z)) return false;
  return true;
}

export function ladnyKod(kod) {
  return kod.match(/.{1,4}/g).join('-');
}

export function nowyKod() {
  const losowe = globalThis.crypto.getRandomValues(new Uint8Array(DLUGOSC_KODU));
  let kod = '';
  for (const b of losowe) kod += ALFABET[b & 31]; // 256 dzieli sie przez 32, wiec bez przechylenia
  return kod;
}

async function kluczZKodu(kod, sol, powtorzenia) {
  const baza = await subtle().importKey('raw', tekst.encode(kod), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: sol, iterations: powtorzenia },
    baza, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function zamknij(opis, kod, powtorzenia = POWTORZENIA) {
  const sol = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const klucz = await kluczZKodu(kod, sol, powtorzenia);
  const szyfr = await subtle().encrypt({ name: 'AES-GCM', iv }, klucz, tekst.encode(JSON.stringify(opis)));
  return { v: 1, kdf: 'PBKDF2-SHA256', powtorzenia, sol: b64(sol), iv: b64(iv), szyfr: b64(szyfr) };
}

// Zwraca opis wydania albo rzuca ZlyKod. Zly kod i uszkodzony zamek wygladaja tak samo (GCM).
export async function otworz(zamek, kod) {
  if (!zamek || zamek.v !== 1 || zamek.kdf !== 'PBKDF2-SHA256') throw new Error('nieznany format zamka');
  const klucz = await kluczZKodu(kod, zB64(zamek.sol), zamek.powtorzenia);
  let jawne;
  try {
    jawne = await subtle().decrypt({ name: 'AES-GCM', iv: zB64(zamek.iv) }, klucz, zB64(zamek.szyfr));
  } catch {
    throw new ZlyKod();
  }
  return JSON.parse(new TextDecoder().decode(jawne));
}

function ivBloku(prefiks, numer) {
  const iv = new Uint8Array(12);
  iv.set(prefiks, 0);
  new DataView(iv.buffer).setBigUint64(4, BigInt(numer));
  return iv;
}

function aadBloku(numer, ostatni) {
  const aad = new Uint8Array(9);
  new DataView(aad.buffer).setBigUint64(0, BigInt(numer));
  aad[8] = ostatni ? 1 : 0;
  return aad;
}

export async function kluczPliku(surowy, uzycie) {
  return subtle().importKey('raw', surowy, 'AES-GCM', false, [uzycie]);
}

export async function szyfrujBlok(klucz, prefiks, numer, ostatni, dane) {
  return new Uint8Array(await subtle().encrypt(
    { name: 'AES-GCM', iv: ivBloku(prefiks, numer), additionalData: aadBloku(numer, ostatni) }, klucz, dane));
}

export async function odszyfrujBlok(klucz, prefiks, numer, ostatni, dane) {
  return new Uint8Array(await subtle().decrypt(
    { name: 'AES-GCM', iv: ivBloku(prefiks, numer), additionalData: aadBloku(numer, ostatni) }, klucz, dane));
}

// Rozklada pobrana czesc na bloki i odszyfrowuje je. Zwraca liste kawalkow jawnych.
// plik: { rozmiar, blok, czesci:[{adres, rozmiar, bloki}] }, numerCzesci: indeks w plik.czesci.
export async function odszyfrujCzesc(plik, klucz, prefiks, numerCzesci, dane) {
  const wszystkieBloki = Math.max(1, Math.ceil(plik.rozmiar / plik.blok));
  let pierwszy = 0;
  for (let i = 0; i < numerCzesci; i++) pierwszy += plik.czesci[i].bloki;
  const czesc = plik.czesci[numerCzesci];
  if (dane.byteLength !== czesc.rozmiar) throw new Error(`czesc ${numerCzesci + 1} ma zly rozmiar`);
  const wynik = [];
  let pozycja = 0;
  for (let k = 0; k < czesc.bloki; k++) {
    const numer = pierwszy + k;
    const ostatni = numer === wszystkieBloki - 1;
    const dlugosc = ostatni ? plik.rozmiar - numer * plik.blok + TAG : plik.blok + TAG;
    wynik.push(await odszyfrujBlok(klucz, prefiks, numer, ostatni, dane.subarray(pozycja, pozycja + dlugosc)));
    pozycja += dlugosc;
  }
  if (pozycja !== dane.byteLength) throw new Error(`czesc ${numerCzesci + 1} ma nadmiarowe bajty`);
  return wynik;
}

// ---------- Karta pobierania (podpis Ed25519 wydawcy) ----------
// Klucze publiczne lancucha wydan, test pilnuje zgodnosci z repo: glowny (zasobnik/wydanie/klucz-publiczny.txt)
// i zapasowy na wypadek utraty glownego (zasobnik/wydanie/klucz-zapasowy.txt). Karta podpisana ktorymkolwiek przechodzi.
export const KLUCZ_PUBLICZNY = 'sQuGHbpx34bf43UtQSt/kHSrDArj+fERqBjCz/XgKN0=';
export const KLUCZ_ZAPASOWY = '4aDAEk6jb2GFbNWYCpN3n0qJHAv3fpUWfuh1auzBCbQ=';
export const KLUCZE_ZAUFANE = [KLUCZ_PUBLICZNY, KLUCZ_ZAPASOWY];
// Podpis obejmuje ten prefiks i bajty danych (zasobnik/wydanie/karta.go, PrefiksKarty).
const PREFIKS_KARTY = 'rygiel-strona-v1\0';

export class ZlyPodpis extends Error {
  constructor(powod) { super(`karta: ${powod}`); this.name = 'ZlyPodpis'; }
}
export class BrakEd25519 extends Error {
  constructor() { super('przegladarka nie ma Ed25519 w WebCrypto'); this.name = 'BrakEd25519'; }
}

// Zwraca dane karty (wersja, data, zmiany, plik {nazwa, rozmiar, sha256}) albo rzuca ZlyPodpis / BrakEd25519.
// klucze: lista kluczy w base64 (domyslnie glowny i zapasowy) albo jeden klucz jako tekst.
export async function sprawdzKarte(koperta, klucze = KLUCZE_ZAUFANE) {
  const k = typeof koperta === 'string' ? JSON.parse(koperta) : koperta;
  if (!k || k.format !== 1 || Object.keys(k).sort().join() !== 'dane,format,podpis') throw new ZlyPodpis('koperta');
  const lista = [];
  try {
    for (const kluczB64 of [klucze].flat()) {
      lista.push(await subtle().importKey('raw', zB64(kluczB64), { name: 'Ed25519' }, false, ['verify']));
    }
  } catch {
    throw new BrakEd25519();
  }
  const dane = zB64(k.dane);
  const prefiks = tekst.encode(PREFIKS_KARTY);
  const podpisane = new Uint8Array(prefiks.length + dane.length);
  podpisane.set(prefiks, 0);
  podpisane.set(dane, prefiks.length);
  let pasuje = false;
  for (const klucz of lista) if (!pasuje && await subtle().verify({ name: 'Ed25519' }, klucz, zB64(k.podpis), podpisane)) pasuje = true;
  if (!pasuje) throw new ZlyPodpis('podpis');
  const karta = JSON.parse(new TextDecoder().decode(dane));
  const p = karta.plik;
  if (karta.produkt !== 'rygiel-strona' || !/^\d+\.\d+\.\d+$/.test(karta.wersja) || karta.tag !== `v${karta.wersja}`
    || !p || !/^[\w.-]{1,64}$/.test(p.nazwa) || !Number.isSafeInteger(p.rozmiar) || p.rozmiar <= 0
    || !/^[0-9a-f]{64}$/.test(p.sha256) || !Array.isArray(karta.zmiany) || !karta.zmiany.length
    || !karta.zmiany.every((z) => typeof z === 'string')) throw new ZlyPodpis('pola');
  return karta;
}

export async function sha256Hex(dane) {
  const skrot = new Uint8Array(await subtle().digest('SHA-256', dane));
  return [...skrot].map((b) => b.toString(16).padStart(2, '0')).join('');
}
