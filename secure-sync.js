// secure-sync.js — portabler, Ende-zu-Ende verschlüsselter GitHub-Sync.
// Aus dem PKV-Dashboard herausgelöst und projektunabhängig gemacht.
//
// Modell:
//   PIN  --PBKDF2-->  pinKey        verschlüsselt Token/API-Key im localStorage
//   pinKey            --umschlägt-->  dataKey (32 zufällige Bytes)
//   dataKey           verschlüsselt  Datenstand (Gist) und Dateien (Repo)
// Der dataKey reist als "tresor" im Gist mit, damit ein neues Gerät nur die PIN braucht.
// GitHub sieht nie Klartext.

const ITER_PIN = 310000;   // PIN -> Arbeitsschlüssel
const ITER_SETUP = 600000; // Einrichtungs-Passwort (Datei liegt öffentlich)

const b64 = bytes => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s); };
const b64ab = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);

export class SecureSync {
  /**
   * @param {object} o
   * @param {string} o.ns          Namespace für Storage-Keys, z. B. 'rezepte'
   * @param {string} o.header      Magic-Header für verschlüsselte Dateien, z. B. 'REZENC1' (7 Zeichen!)
   * @param {string} o.gistFile    Dateiname im Gist, z. B. 'rezepte-stand.json'
   * @param {string} [o.gistDescription]
   * @param {(msg:string)=>void} [o.onStatus]
   */
  constructor({ ns, header, gistFile, gistDescription, onStatus }) {
    if (!ns || !header || !gistFile) throw new Error('ns, header und gistFile sind nötig');
    if (header.length !== 7) throw new Error('header muss genau 7 Zeichen haben');
    this.ns = ns; this.header = header; this.gistFile = gistFile;
    this.gistDescription = gistDescription || ns + ' — privater Datenstand';
    this.onStatus = onStatus || (() => {});
    this.cfg = { token: '', gistId: '', repo: '', aiKey: '' };
    this._pin = null; this._pinKey = null; this._pinSalt = null; this._dataKey = null;
    const roh = this._raw('sync');
    if (roh && !roh.enc) this.cfg = { token: roh.token || '', gistId: roh.gistId || '', repo: roh.repo || '', aiKey: roh.aiKey || '' };
    else if (roh) this.cfg = { token: '', gistId: roh.gistId || '', repo: roh.repo || '', aiKey: '' };
  }

  // ---------- Storage ----------
  _k(name) { return this.ns + '.' + name + '.v1'; }
  _raw(name) { try { return JSON.parse(localStorage.getItem(this._k(name)) || 'null'); } catch (e) { return null; } }
  get verschluesselt() { const r = this._raw('sync'); return !!(r && r.enc); }
  get entsperrt() { return !!this._pinKey; }

  // ---------- Schlüssel ----------
  async _import(bytes) {
    const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { key, raw: b64(bytes) };
  }
  async _fromPin(pin, saltB64) {
    const mat = await crypto.subtle.importKey('raw', enc(pin), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64ab(saltB64), iterations: ITER_PIN, hash: 'SHA-256' }, mat, 256);
    return this._import(new Uint8Array(bits));
  }
  async pinHash(pin) {
    const buf = await crypto.subtle.digest('SHA-256', enc(this.ns + ':' + pin));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** PIN prüfen (gegen den Hash aus deinen Settings) und Schlüssel aufbauen. */
  async unlock(pin, sperreHash) {
    if (sperreHash && await this.pinHash(pin) !== sperreHash) return false;
    this._pin = pin;
    const roh = this._raw('sync');
    if (roh && roh.enc) {
      const k = await this._fromPin(pin, roh.salt);
      const klar = JSON.parse(dec(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(roh.iv) }, k.key, b64ab(roh.enc))));
      this._pinKey = k.key; this._pinSalt = roh.salt;
      this.cfg = { token: klar.token || '', aiKey: klar.aiKey || '', gistId: roh.gistId || '', repo: roh.repo || '' };
      sessionStorage.setItem(this.ns + '.schluessel', k.raw);
    } else {
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const k = await this._fromPin(pin, salt);
      this._pinKey = k.key; this._pinSalt = salt;
      sessionStorage.setItem(this.ns + '.schluessel', k.raw);
      await this.setConfig(this.cfg);
    }
    await this.dataKey(null);
    return true;
  }

  /** Nach Reload ohne PIN-Eingabe: Sitzungsschlüssel aus sessionStorage übernehmen. */
  async resume() {
    const raw = sessionStorage.getItem(this.ns + '.schluessel');
    const roh = this._raw('sync');
    if (!raw || !roh || !roh.enc) return false;
    try {
      const k = await this._import(b64ab(raw));
      const klar = JSON.parse(dec(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(roh.iv) }, k.key, b64ab(roh.enc))));
      this._pinKey = k.key; this._pinSalt = roh.salt;
      this.cfg = { token: klar.token || '', aiKey: klar.aiKey || '', gistId: roh.gistId || '', repo: roh.repo || '' };
      await this.dataKey(null);
      return true;
    } catch (e) { sessionStorage.removeItem(this.ns + '.schluessel'); return false; }
  }

  lock() {
    this._pin = null; this._pinKey = null; this._dataKey = null;
    sessionStorage.removeItem(this.ns + '.schluessel');
    sessionStorage.removeItem(this.ns + '.datenschluessel');
    this.cfg = { ...this.cfg, token: '', aiKey: '' };
  }

  /** Token/Gist-ID/Repo/API-Key setzen — Geheimnisse werden mit der PIN verschlüsselt abgelegt. */
  async setConfig(c) {
    this.cfg = { ...this.cfg, ...c };
    const v = this.cfg;
    if (this._pinKey && this._pinSalt && (v.token || v.aiKey)) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this._pinKey, enc(JSON.stringify({ token: v.token || '', aiKey: v.aiKey || '' })));
      localStorage.setItem(this._k('sync'), JSON.stringify({ enc: b64(new Uint8Array(ct)), iv: b64(iv), salt: this._pinSalt, gistId: v.gistId || '', repo: v.repo || '' }));
    } else {
      localStorage.setItem(this._k('sync'), JSON.stringify(v));
    }
  }

  /** PIN wechseln: Token-Tresor und Datenschlüssel-Umschlag neu verschlüsseln, Daten bleiben unverändert. */
  async changePin(neu) {
    const dk = sessionStorage.getItem(this.ns + '.datenschluessel');
    this._pin = neu;
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const k = await this._fromPin(neu, salt);
    this._pinKey = k.key; this._pinSalt = salt;
    sessionStorage.setItem(this.ns + '.schluessel', k.raw);
    await this.setConfig(this.cfg);
    if (dk) {
      const bytes = b64ab(dk);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k.key, bytes);
      const t = { salt, iv: b64(iv), key: b64(new Uint8Array(ct)) };
      this._tresorSig = t.salt + '|' + t.iv + '|' + t.key;
      localStorage.setItem(this._k('tresor'), JSON.stringify(t));
    }
    return await this.pinHash(neu);
  }

  // ---------- Datenschlüssel (Umschlag-Verschlüsselung) ----------
  /**
   * Liefert den gemeinsamen Datenschlüssel. Wird ein Umschlag (tresor) mitgegeben —
   * etwa der aus dem Gist —, hat der Vorrang vor allem, was dieses Gerät gespeichert hat.
   * Sonst legen zwei Geräte je einen eigenen Schlüssel an und können sich nicht mehr lesen.
   */
  async dataKey(tresor) {
    const sig = t => t ? (t.salt + '|' + t.iv + '|' + t.key) : null;
    const fremd = sig(tresor);
    if (this._dataKey && (!fremd || fremd === this._tresorSig)) return this._dataKey;
    if (fremd && this._pin) {
      try {
        const k = await this._fromPin(this._pin, tresor.salt);
        const bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(tresor.iv) }, k.key, b64ab(tresor.key)));
        const imp = await this._import(bytes);
        this._dataKey = imp.key; this._tresorSig = fremd;
        sessionStorage.setItem(this.ns + '.datenschluessel', imp.raw);
        localStorage.setItem(this._k('tresor'), JSON.stringify(tresor));
        return this._dataKey;
      } catch (e) {}
    }
    if (this._dataKey) return this._dataKey;
    const raw = sessionStorage.getItem(this.ns + '.datenschluessel');
    if (raw) {
      try {
        this._dataKey = (await this._import(b64ab(raw))).key;
        this._tresorSig = sig(this._raw('tresor'));
        return this._dataKey;
      } catch (e) {}
    }
    const t = this._raw('tresor');
    if (t && this._pin) {
      try {
        const k = await this._fromPin(this._pin, t.salt);
        const bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(t.iv) }, k.key, b64ab(t.key)));
        const imp = await this._import(bytes);
        this._dataKey = imp.key; this._tresorSig = sig(t);
        sessionStorage.setItem(this.ns + '.datenschluessel', imp.raw);
        return this._dataKey;
      } catch (e) {}
    }
    if (this._pin) return this._dataKeyNeu();
    return null;
  }
  async _dataKeyNeu() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const imp = await this._import(bytes);
    this._dataKey = imp.key;
    sessionStorage.setItem(this.ns + '.datenschluessel', imp.raw);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const k = await this._fromPin(this._pin, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k.key, bytes);
    const t = { salt, iv: b64(iv), key: b64(new Uint8Array(ct)) };
    this._tresorSig = t.salt + '|' + t.iv + '|' + t.key;
    localStorage.setItem(this._k('tresor'), JSON.stringify(t));
    return this._dataKey;
  }
  tresorRoh() { return this._raw('tresor'); }

  // ---------- GitHub ----------
  _headers(extra) { return { Authorization: 'Bearer ' + this.cfg.token, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json', ...(extra || {}) }; }

  /** Datenstand (beliebiges JSON-Objekt) verschlüsselt in den privaten Gist schreiben. */
  /**
   * Sucht in den eigenen Gists den ältesten, der die Zustandsdatei enthält.
   * Damit findet ein neues Gerät den vorhandenen Stand, statt einen zweiten anzulegen.
   */
  async findGist() {
    if (!this.cfg.token) return '';
    try {
      const treffer = [];
      for (let seite = 1; seite <= 3; seite++) {
        const r = await fetch('https://api.github.com/gists?per_page=100&page=' + seite, { headers: this._headers() });
        if (!r.ok) return '';
        const liste = await r.json();
        if (!Array.isArray(liste) || !liste.length) break;
        liste.forEach(g => { if (g.files && g.files[this.gistFile]) treffer.push(g); });
        if (liste.length < 100) break;
      }
      if (!treffer.length) return '';
      treffer.sort((a, b) => (a.created_at || '') < (b.created_at || '') ? -1 : 1);
      return treffer[0].id;
    } catch (e) { return ''; }
  }

  /**
   * Holt nur den Umschlag aus dem Gist, ohne zu entschlüsseln. Damit kann ein Gerät
   * vor dem ersten Hochladen den gemeinsamen Datenschlüssel übernehmen.
   */
  async fernTresor() {
    if (!this.cfg.token || !this.cfg.gistId) return null;
    if (this._tresorSig) return null; // schon einen gemeinsamen Schlüssel — kein Abruf nötig
    try {
      const r = await fetch('https://api.github.com/gists/' + this.cfg.gistId.trim(), { headers: this._headers() });
      if (!r.ok) return null;
      const j = await r.json();
      const f = j.files && j.files[this.gistFile];
      if (!f) return null;
      const s = JSON.parse(f.truncated ? await (await fetch(f.raw_url)).text() : f.content);
      return s && s.verschluesselt ? (s.tresor || null) : null;
    } catch (e) { return null; }
  }

  async uploadState(stand, { sperreHash } = {}) {
    if (!this.cfg.token) throw new Error('Kein GitHub-Token hinterlegt.');
    const gespeichert = stand.gespeichert || new Date().toISOString();
    let inhalt;
    if (!this.cfg.gistId) {
      const gefunden = await this.findGist();
      if (gefunden) await this.setConfig({ gistId: gefunden });
    }
    // Erst den Umschlag des Gists übernehmen, sonst schreibt dieses Gerät mit
    // einem eigenen Schlüssel und sperrt alle anderen aus.
    const key = await this.dataKey(await this.fernTresor());
    if (key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc(JSON.stringify({ ...stand, gespeichert })));
      inhalt = JSON.stringify({ verschluesselt: true, gespeichert, sperreHash: sperreHash || null, tresor: this.tresorRoh(), iv: b64(iv), daten: b64(new Uint8Array(ct)) }, null, 1);
    } else {
      inhalt = JSON.stringify({ ...stand, gespeichert }, null, 1);
    }
    const files = { [this.gistFile]: { content: inhalt } };
    const r = this.cfg.gistId
      ? await fetch('https://api.github.com/gists/' + this.cfg.gistId.trim(), { method: 'PATCH', headers: this._headers(), body: JSON.stringify({ files }) })
      : await fetch('https://api.github.com/gists', { method: 'POST', headers: this._headers(), body: JSON.stringify({ description: this.gistDescription, public: false, files }) });
    if (!r.ok) throw new Error('GitHub-Fehler ' + r.status + (r.status === 401 ? ' — Token ungültig?' : r.status === 404 ? ' — Gist-ID falsch oder Token ohne Gist-Recht?' : ''));
    const j = await r.json();
    if (!this.cfg.gistId && j.id) await this.setConfig({ gistId: j.id });
    localStorage.setItem(this.ns + '.sync.ts', gespeichert);
    return { gistId: this.cfg.gistId, gespeichert };
  }

  /**
   * Datenstand laden. Ergebnis:
   *   { stand }                      entschlüsselt und lesbar
   *   { gesperrt: true, sperreHash } verschlüsselt, PIN fehlt
   */
  async downloadState() {
    if (!this.cfg.token || !this.cfg.gistId) throw new Error('Token und Gist-ID nötig.');
    const r = await fetch('https://api.github.com/gists/' + this.cfg.gistId.trim(), { headers: this._headers() });
    if (!r.ok) throw new Error('GitHub-Fehler ' + r.status);
    const j = await r.json();
    const f = j.files && j.files[this.gistFile];
    if (!f) throw new Error(this.gistFile + ' nicht im Gist gefunden');
    let s = JSON.parse(f.truncated ? await (await fetch(f.raw_url)).text() : f.content);
    if (s && s.verschluesselt) {
      const key = await this.dataKey(s.tresor);
      if (!key) return { gesperrt: true, sperreHash: s.sperreHash || null };
      try {
        s = JSON.parse(dec(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(s.iv) }, key, b64ab(s.daten))));
      } catch (e) {
        throw new Error('Stand lässt sich mit dieser PIN nicht entschlüsseln.');
      }
    }
    return { stand: s };
  }

  // ---------- Dateien im privaten Repo ----------
  _repo() { const c = this.cfg; return c.token && c.repo && c.repo.includes('/') ? c.repo.trim() : null; }

  async encryptFile(file) {
    const key = await this.dataKey(null);
    if (!key) return null;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer()));
    const kopf = enc(this.header);
    const alles = new Uint8Array(kopf.length + 12 + ct.length);
    alles.set(kopf, 0); alles.set(iv, kopf.length); alles.set(ct, kopf.length + 12);
    return new Blob([alles]);
  }

  /** Datei verschlüsselt ins private Repo legen (pfad z. B. 'belege/42-rechnung.pdf'). */
  async uploadFile(pfad, file) {
    const repo = this._repo();
    if (!repo) throw new Error('Kein privates Repo hinterlegt.');
    const zuSenden = await this.encryptFile(file);
    if (!zuSenden) throw new Error('Zum verschlüsselten Hochladen bitte mit der PIN entsperren.');
    const inhalt = b64(new Uint8Array(await zuSenden.arrayBuffer()));
    const url = 'https://api.github.com/repos/' + repo + '/contents/' + pfad;
    let sha = null;
    const g = await fetch(url, { headers: this._headers() });
    if (g.ok) sha = (await g.json()).sha;
    const r = await fetch(url, { method: 'PUT', headers: this._headers(), body: JSON.stringify({ message: 'Datei: ' + pfad, content: inhalt, ...(sha ? { sha } : {}) }) });
    if (!r.ok) throw new Error('GitHub-Fehler ' + r.status + (r.status === 404 ? ' — Repo falsch oder Token ohne Contents-Recht?' : ''));
    return true;
  }

  /** Datei laden und entschlüsseln. Gibt File zurück oder null. */
  async downloadFile(pfad, name, mime) {
    const repo = this._repo();
    if (!repo) return null;
    const r = await fetch('https://api.github.com/repos/' + repo + '/contents/' + pfad, { headers: this._headers({ Accept: 'application/vnd.github.raw' }) });
    if (!r.ok) return null;
    const roh = await r.blob();
    let inhalt = roh, warKlartext = true;
    const kopf = dec(new Uint8Array(await roh.slice(0, 7).arrayBuffer()));
    if (kopf === this.header) {
      warKlartext = false;
      const key = await this.dataKey(null);
      if (!key) { this.onStatus('Datei ist verschlüsselt — bitte mit der PIN entsperren.'); return null; }
      const alles = new Uint8Array(await roh.arrayBuffer());
      inhalt = new Blob([await crypto.subtle.decrypt({ name: 'AES-GCM', iv: alles.subarray(7, 19) }, key, alles.subarray(19))]);
    }
    const typ = mime || (/\.pdf$/i.test(name || '') ? 'application/pdf' : (warKlartext && roh.type && roh.type !== 'text/plain' ? roh.type : 'image/jpeg'));
    const datei = new File([inhalt], name || 'datei', { type: typ });
    datei.warKlartext = warKlartext; // für schleichende Migration
    return datei;
  }

  async deleteFile(pfad) {
    const repo = this._repo();
    if (!repo) return false;
    const url = 'https://api.github.com/repos/' + repo + '/contents/' + pfad;
    const g = await fetch(url, { headers: this._headers() });
    if (!g.ok) return false;
    const sha = (await g.json()).sha;
    const r = await fetch(url, { method: 'DELETE', headers: this._headers(), body: JSON.stringify({ message: 'Löschen: ' + pfad, sha }) });
    return r.ok;
  }

  // ---------- Schnell-Einrichtung: verschlüsselte setup.json neben der index.html ----------
  async _setupKey(pass, salt) {
    const mat = await crypto.subtle.importKey('raw', enc(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER_SETUP, hash: 'SHA-256' }, mat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  /** Gibt den JSON-Text für setup.json zurück (Passwort min. 8 Zeichen). */
  async setupErzeugen(pass) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this._setupKey(pass, salt);
    const c = this.cfg;
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc(JSON.stringify({ token: c.token, gistId: c.gistId, repo: c.repo, aiKey: c.aiKey })));
    return JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), daten: b64(new Uint8Array(ct)) }, null, 1);
  }
  /** setup.json holen (oder null) — für die Einrichtung neuer Geräte. */
  async setupHolen(url) {
    try { const r = await fetch(url || 'setup.json'); if (!r.ok) return null; const b = await r.json(); return b && b.daten ? b : null; } catch (e) { return null; }
  }
  async setupAnwenden(pass, blob) {
    const key = await this._setupKey(pass, b64ab(blob.salt));
    const klar = JSON.parse(dec(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ab(blob.iv) }, key, b64ab(blob.daten))));
    if (!klar.token) throw new Error('unvollständig');
    await this.setConfig({ token: klar.token, gistId: klar.gistId || '', repo: klar.repo || '', aiKey: klar.aiKey || '' });
    return this.cfg;
  }
}
