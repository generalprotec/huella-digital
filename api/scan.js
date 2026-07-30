const https = require('https');

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, {
      headers: { 'User-Agent': 'HuellaDigital/1.0', Accept: 'application/json' },
      timeout: 12000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON from ' + url)); }
      });
    }).on('error', reject).on('timeout', function() { this.destroy(); reject(new Error('Timeout: ' + url)); });
  });
}

function extractFromVcard(props) {
  if (!props || !Array.isArray(props)) return null;
  const g = (n) => { const p = props.find(x => x[0] === n); if (!p) return ''; return typeof p[3] === 'string' ? p[3] : ''; };
  const org = g('org');
  const fn = g('fn');
  if (!org && !fn) return null;
  const adrP = props.find(x => x[0] === 'adr');
  let addr = '';
  if (adrP) {
    const v = adrP[3];
    addr = Array.isArray(v) ? v.filter(x => x && String(x).trim() && !String(x).includes('REDACTED')).join(', ') : (typeof v === 'string' && !v.includes('REDACTED') ? v : '');
  }
  const e = g('email');
  const p = g('tel');
  return {
    organization: org || fn,
    name: fn !== org ? fn : '',
    email: e && !e.includes('REDACTED') ? e : '',
    phone: p && !p.includes('REDACTED') ? p : '',
    address: addr,
  };
}

function findRegistrant(rdap) {
  if (!rdap || !rdap.entities) return null;
  for (const e of rdap.entities) {
    const roles = (e.roles || []).map(r => r.toLowerCase());
    if (roles.includes('registrant') && e.vcardArray) {
      const vc = e.vcardArray;
      if (Array.isArray(vc) && vc[0] === 'vcard' && Array.isArray(vc[1])) {
        const r = extractFromVcard(vc[1]);
        if (r && r.organization) return r;
      }
    }
  }
  return null;
}

function findRegistrarLink(rdap) {
  if (!rdap || !rdap.links) return null;
  for (const l of rdap.links) {
    if (l.rel === 'related' && l.href && !l.href.includes('verisign')) {
      return l.href;
    }
  }
  return null;
}

function getEvents(rdap) {
  if (!rdap || !rdap.events) return {};
  const ev = (n) => { const e = rdap.events.find(x => x.eventAction === n); return e ? e.eventDate : ''; };
  return {
    creationDate: ev('registration'),
    expiryDate: ev('expiration'),
    lastChanged: ev('last changed'),
  };
}

const RDAP_URLS = {
  com: 'https://rdap.verisign.com/com/v1/domain/',
  net: 'https://rdap.verisign.com/net/v1/domain/',
  org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
  info: 'https://rdap.afilias.net/rdap/domain/',
  io: 'https://rdap.nic.io/domain/',
  co: 'https://rdap.nic.co/domain/',
  es: 'https://rdap.nic.es/domain/',
  dev: 'https://rdap.nic.dev/domain/',
  app: 'https://rdap.nic.app/domain/',
  cloud: 'https://rdap.nic.cloud/domain/',
  me: 'https://rdap.nic.me/domain/',
  uk: 'https://rdap.nominet.uk/domain/',
  eu: 'https://rdap.eu/domain/',
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS, GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let domain = '';
  if (req.method === 'GET') domain = (req.query && req.query.domain) || '';
  else if (req.method === 'POST') domain = ((req.body && (req.body.domain || req.body.d)) || '');

  domain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Dominio inválido' });

  const result = { domain, timestamp: new Date().toISOString(), company: null };

  try {
    const tld = domain.split('.').pop();
    const url = RDAP_URLS[tld] ? RDAP_URLS[tld] + domain : `https://rdap.org/domain/${domain}`;
    const rdap1 = await fetch(url).catch(() => null);
    if (!rdap1) return res.json({ ...result, error: 'RDAP no disponible para este dominio' });

    let company = findRegistrant(rdap1);

    // If no registrant found, try registrar's RDAP
    if (!company) {
      const regLink = findRegistrarLink(rdap1);
      if (regLink) {
        const rdap2 = await fetch(regLink).catch(() => null);
        if (rdap2) company = findRegistrant(rdap2);
      }
    }

    const events = getEvents(rdap1);
    const ns = (rdap1.nameservers || []).map(n => n.ldhName || n).filter(Boolean);
    const port43 = (rdap1.port43 || '').replace('whois.', '').replace('.whois-servers.net', '');

    if (company) {
      result.company = { ...company, ...events, registrar: port43, nameservers: ns };
    } else if (events.creationDate || ns.length) {
      result.company = { organization: '', ...events, registrar: port43, nameservers: ns };
    }

  } catch (e) {
    result.error = e.message;
  }

  res.json(result);
};
