const https = require('https');

const HIBP_KEY = process.env.HIBP_API_KEY || '';

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'HuellaDigital/1.0', Accept: 'application/json' }, timeout: 12000 }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(data)); } catch { resolve(data); }
      });
    }).on('error', reject);
  });
}

function fetchRDAP(domain) {
  const tld = domain.split('.').pop().toLowerCase();
  const urls = {
    com: 'https://rdap.verisign.com/com/v1/domain/',
    net: 'https://rdap.verisign.com/net/v1/domain/',
    org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
    info: 'https://rdap.afilias.net/rdap/domain/',
    io: 'https://rdap.nic.io/domain/',
    co: 'https://rdap.nic.co/domain/',
    dev: 'https://rdap.nic.dev/domain/',
    app: 'https://rdap.nic.app/domain/',
    cloud: 'https://rdap.nic.cloud/domain/',
    es: 'https://rdap.nic.es/domain/',
  };
  const url = urls[tld] ? urls[tld] + domain : `https://rdap.org/domain/${domain}`;
  return fetch(url);
}

function extractEntity(data) {
  if (!data || !data.entities) return null;
  for (const e of data.entities) {
    const roles = (e.roles || []).map(r => r.toLowerCase());
    if (roles.includes('registrant') || roles.includes('administrative') || !e.roles || e.roles.length === 0) {
      const vcard = e.vcardArray && e.vcardArray[1] || [];
      const get = (n) => { const f = vcard.find(v => v[0] === n); return f ? f[3] || f[1] || '' : ''; };
      return {
        name: get('fn'),
        org: get('org'),
        email: get('email'),
        phone: get('tel'),
        address: (get('adr') && typeof get('adr') === 'object') ? [get('adr').filter(v => v && v !== '').join(', ')].filter(Boolean).join(' ') : get('adr'),
        role: e.roles ? e.roles.join(', ') : 'registrant',
      };
    }
  }
  return null;
}

async function queryHIBP(domain) {
  if (!HIBP_KEY) return [];
  try {
    const data = await fetch(`https://haveibeenpwned.com/api/v3/breaches?domain=${domain}`);
    return Array.isArray(data) ? data.map(b => ({ name: b.Name, date: b.BreachDate, count: b.PwnCount || '?' })) : [];
  } catch { return []; }
}

module.exports = async (req, res) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let domain = ((req.body && (req.body.domain || req.body.d)) || '').trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Dominio inválido' });

  const result = { domain, timestamp: new Date().toISOString(), company: null, breaches: [] };

  try {
    const [rdap, hibp] = await Promise.all([
      fetchRDAP(domain).catch(() => null),
      queryHIBP(domain),
    ]);
    result.breaches = hibp;

    if (rdap) {
      const events = rdap.events || [];
      const ev = (n) => { const e = events.find(v => v.eventAction === n); return e ? e.eventDate : ''; };
      result.company = {
        name: rdap.rdapConformance ? (extractEntity(rdap) || {}).org || (extractEntity(rdap) || {}).name || rdap.name || '' : rdap.name || '',
        organization: (extractEntity(rdap) || {}).org || (extractEntity(rdap) || {}).name || '',
        email: (extractEntity(rdap) || {}).email || '',
        phone: (extractEntity(rdap) || {}).phone || '',
        address: (extractEntity(rdap) || {}).address || '',
        contacts: (rdap.entities || []).map(e => {
          const v = e.vcardArray && e.vcardArray[1] || [];
          const g = (n) => { const f = v.find(x => x[0] === n); return f ? f[3] || f[1] || '' : ''; };
          return { role: (e.roles || []).join(', '), name: g('fn'), email: g('email') };
        }).filter(c => c.name || c.email),
        registrar: rdap.port43 ? rdap.port43.replace('whois.', '').replace('.whois-servers.net', '') : '',
        nameservers: (rdap.nameservers || []).map(n => n.ldhName || n),
        creationDate: ev('registration'),
        expiryDate: ev('expiration'),
        lastChanged: ev('last changed'),
      };
    }
  } catch (e) {
    result.error = e.message;
  }

  res.json(result);
};
