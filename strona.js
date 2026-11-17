// Rygiel: strona pobierania na kod. Bez kodu strona zna tylko zaszyfrowany zamek.json.
// Po otwarciu zamka: podpisana karta wydania (Ed25519, ten sam klucz co aktualizacje), klucz
// zaszyfrowanej kopii pliku i kroki. Plik trafia na dysk dopiero, gdy jego SHA-256 zgadza sie z karta.
import {
  otworz, ZlyKod, ZlyPodpis, BrakEd25519, normalizujKod, poprawnyKsztalt, sprawdzKarte,
  kluczPliku, odszyfrujCzesc, sha256Hex, zB64,
} from './zamek.js';

const $ = (id) => document.getElementById(id);
const MB = 1024 * 1024;
const mb = (bajty) => `${(bajty / MB).toLocaleString('pl-PL', { maximumFractionDigits: 1 })} MB`;
const dataPl = (iso) => new Date(`${iso}T12:00:00Z`).toLocaleDateString('pl-PL', { day: 'numeric', month: 'long', year: 'numeric' });

let zamek = null;
let opis = null;
let karta = null;
let adresPliku = null;

async function wczytajZamek() {
  if (zamek) return zamek;
  const odp = await fetch('zamek.json', { cache: 'no-store' });
  if (!odp.ok) throw new Error(`zamek.json: HTTP ${odp.status}`);
  zamek = await odp.json();
  return zamek;
}

// ---------- Rosnace opoznienie prob (po stronie klienta, przezywa odswiezenie strony) ----------
// Po n-tej nieudanej probie: 2^(n-1) s przerwy, najwyzej 5 min. Udane otwarcie zeruje licznik.
// To tylko hamulec dla czlowieka: prawdziwa ochrona to 80 bitow kodu i PBKDF2.
const KLUCZ_PROB = 'rygiel-proby';
const MAKS_PRZERWA = 300;

function stanProb() {
  try {
    const s = JSON.parse(localStorage.getItem(KLUCZ_PROB) ?? 'null');
    if (s && Number.isInteger(s.n) && typeof s.do === 'number') return s;
  } catch { /* brak dostepu albo zly zapis: od zera */ }
  return { n: 0, do: 0 };
}

function zapiszProby(s) {
  try { localStorage.setItem(KLUCZ_PROB, JSON.stringify(s)); } catch { /* tryb bez zapisu: licznik tylko w pamieci */ }
  pamiecProb = s;
}

let pamiecProb = stanProb();
let odliczanie = null;

function nieudanaProba() {
  const n = Math.max(stanProb().n, pamiecProb.n) + 1;
  const przerwa = Math.min(2 ** (n - 1), MAKS_PRZERWA);
  zapiszProby({ n, do: Date.now() + przerwa * 1000 });
  odliczaj();
}

function pozostalo() {
  return Math.max(0, Math.ceil((Math.max(stanProb().do, pamiecProb.do) - Date.now()) / 1000));
}

function odliczaj() {
  clearInterval(odliczanie);
  const przycisk = $('otworz');
  const krok = () => {
    const s = pozostalo();
    if (s <= 0) {
      clearInterval(odliczanie);
      przycisk.disabled = false;
      przycisk.textContent = 'Otwórz';
      return;
    }
    przycisk.disabled = true;
    przycisk.textContent = `Odczekaj ${s} s`;
  };
  krok();
  if (pozostalo() > 0) odliczanie = setInterval(krok, 250);
}

// ---------- Formularz kodu ----------
function pokazBladKodu(tekst) {
  const pole = $('kod');
  const blad = $('blad-kodu');
  if (tekst) {
    blad.textContent = tekst;
    blad.hidden = false;
    pole.setAttribute('aria-invalid', 'true');
    pole.focus();
    pole.select();
  } else {
    blad.hidden = true;
    blad.textContent = '';
    pole.setAttribute('aria-invalid', 'false');
  }
}

// Jeden komunikat dla kazdego zlego kodu: bez podpowiedzi o dlugosci i znakach.
const ZLY_KOD = 'Kod nie pasuje.';

$('formularz').addEventListener('submit', async (zdarzenie) => {
  zdarzenie.preventDefault();
  const przycisk = $('otworz');
  if (przycisk.disabled || pozostalo() > 0) return;
  const kod = normalizujKod($('kod').value);
  if (!kod) return pokazBladKodu('Wpisz kod.');
  przycisk.disabled = true;
  przycisk.textContent = 'Sprawdzam';
  let zly = false;
  try {
    if (!poprawnyKsztalt(kod)) throw new ZlyKod();
    opis = await otworz(await wczytajZamek(), kod);
    karta = await sprawdzKarte(opis.karta);
    if (karta.plik.sha256 !== opis.plik.sha256 || karta.plik.rozmiar !== opis.plik.rozmiar) throw new ZlyPodpis('plik');
    zapiszProby({ n: 0, do: 0 });
    pokazBladKodu('');
    pokazWydanie();
  } catch (e) {
    if (e instanceof ZlyKod) {
      zly = true;
      pokazBladKodu(ZLY_KOD);
      nieudanaProba();
    } else if (e instanceof BrakEd25519) {
      pokazBladKodu('Ta przeglądarka nie sprawdzi podpisu pliku. Zaktualizuj ją i spróbuj jeszcze raz.');
    } else if (e instanceof ZlyPodpis) {
      pokazBladKodu('Podpis wydania się nie zgadza. Nie pobieraj pliku i daj znać osobie, która podała kod.');
    } else {
      pokazBladKodu('Nie udało się wczytać strony. Odśwież i spróbuj jeszcze raz.');
    }
  } finally {
    if (!zly) {
      przycisk.disabled = false;
      przycisk.textContent = 'Otwórz';
    }
  }
});

$('kod').addEventListener('input', () => {
  if ($('kod').getAttribute('aria-invalid') === 'true' && pozostalo() === 0) pokazBladKodu('');
});

function lista(id, elementy) {
  $(id).replaceChildren(...elementy.map((t) => {
    const li = document.createElement('li');
    li.textContent = t;
    return li;
  }));
}

function pokazWydanie() {
  const plik = karta.plik;
  $('platforma').textContent = opis.platforma;
  $('wersja').textContent = karta.wersja;
  $('opis-pliku').textContent = `Wydane ${dataPl(karta.data)}, ${plik.nazwa}, ${mb(plik.rozmiar)}`;
  $('pobierz').textContent = `Pobierz (${mb(plik.rozmiar)})`;
  $('suma').textContent = plik.sha256;
  lista('kroki', opis.kroki);
  $('uwaga').textContent = opis.uwaga ?? '';
  $('uwaga').hidden = !opis.uwaga;
  lista('zmiany', karta.zmiany);
  $('zamknieta').hidden = true;
  $('otwarta').hidden = false;
  document.title = `Rygiel ${karta.wersja}`;
  $('pobierz').focus();
}

// ---------- Pobranie, odszyfrowanie i sprawdzenie sumy ----------
async function pobierzCzesc(adres, oczekiwany, postep) {
  const odp = await fetch(adres, { cache: 'no-store' });
  if (!odp.ok) throw new Error(`HTTP ${odp.status}`);
  const dane = new Uint8Array(oczekiwany);
  const czytnik = odp.body.getReader();
  let pozycja = 0;
  for (;;) {
    const { done, value } = await czytnik.read();
    if (done) break;
    if (pozycja + value.length > oczekiwany) throw new Error('za duża część');
    dane.set(value, pozycja);
    pozycja += value.length;
    postep(value.length);
  }
  if (pozycja !== oczekiwany) throw new Error('niepełna część');
  return dane;
}

function zapisz() {
  $('zapisz').click();
}

$('pobierz').addEventListener('click', async () => {
  const przycisk = $('pobierz');
  if (przycisk.disabled) return;
  if (adresPliku) return zapisz();
  const plik = opis.plik;
  const razem = plik.czesci.reduce((s, c) => s + c.rozmiar, 0);
  let pobrane = 0;
  przycisk.disabled = true;
  $('blad-pobierania').hidden = true;
  $('postep').hidden = false;
  const pasek = $('pasek');
  const stan = $('stan');
  const odswiez = () => {
    pasek.value = pobrane / razem;
    stan.textContent = `Pobieram: ${mb(pobrane)} z ${mb(razem)}`;
  };
  odswiez();
  try {
    const klucz = await kluczPliku(zB64(plik.klucz), 'decrypt');
    const prefiks = zB64(plik.prefiks);
    const kawalki = [];
    for (let i = 0; i < plik.czesci.length; i++) {
      let dane;
      try {
        dane = await pobierzCzesc(plik.czesci[i].adres, plik.czesci[i].rozmiar, (n) => { pobrane += n; odswiez(); });
      } catch {
        throw new Error('Pobieranie przerwane. Sprawdź połączenie i spróbuj jeszcze raz.');
      }
      try {
        kawalki.push(...await odszyfrujCzesc(plik, klucz, prefiks, i, dane));
      } catch {
        throw new Error('Plik przyszedł uszkodzony. Spróbuj jeszcze raz.');
      }
    }
    stan.textContent = 'Sprawdzam sumę SHA-256';
    const blob = new Blob(kawalki, { type: 'application/octet-stream' });
    const suma = await sha256Hex(await blob.arrayBuffer());
    // Suma z podpisanej karty, nie z samego zamka: zapis tylko pliku z wydania.
    if (blob.size !== karta.plik.rozmiar || suma !== karta.plik.sha256) {
      throw new Error('Suma pliku nie zgadza się z podpisem. Pliku nie zapisano.');
    }
    adresPliku = URL.createObjectURL(blob);
    const link = $('zapisz');
    link.href = adresPliku;
    link.download = karta.plik.nazwa;
    link.hidden = false;
    pasek.value = 1;
    stan.textContent = `Pobrane: ${karta.plik.nazwa}, suma SHA-256 zgodna.`;
    przycisk.textContent = 'Pobrane';
    zapisz();
  } catch (e) {
    $('postep').hidden = true;
    stan.textContent = '';
    const blad = $('blad-pobierania');
    blad.textContent = e.message;
    blad.hidden = false;
    przycisk.disabled = false;
    przycisk.textContent = 'Pobierz jeszcze raz';
  }
});

// Przerwa z poprzedniej wizyty dalej obowiazuje.
odliczaj();
