const https = require('https');

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, {
      headers: { 'User-Agent': 'HuellaDigital/1.0', Accept: 'application/json' },
      timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); }
      });
    }).on('error', reject).on('timeout', function() { this.destroy(); reject(new Error('Timeout')); });
  });
}

function extractCompany(rdap) {
  if (!rdap || !rdap.entities) return null;
  for (const e of rdap.entities) {
    const vc = e.vcardArray;
    if (!vc || !Array.isArray(vc) || vc[0] !== 'vcard' || !Array.isArray(vc[1])) continue;
    const props = vc[1];
    const get = (name) => {
      const p = props.find(x => x[0] === name);
      if (!p) return '';
      return typeof p[3] === 'string' ? p[3] : typeof p[1] === 'string' ? p[1] : '';
    };
    const name = get('fn');
    const org = get('org');
    const email = get('email');
    const phone = get('tel');
    const adrProp = props.find(x => x[0] === 'adr');
    let address = '';
    if (adrProp) {
      const val = typeof adrProp[3] === 'object' && adrProp[3] ? adrProp[3]
                  : typeof adrProp[1] === 'object' && adrProp[1] ? adrProp[1]
                  : [];
      address = Array.isArray(val) ? val.filter(v => v && String(v).trim()).join(', ') : String(val);
    }
    if (org || name) {
      return { organization: org || name, name, email, phone, address: address || get('adr') };
    }
  }
  return null;
}

module.exports = async (req, res) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS, GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // GET para test
  if (req.method === 'GET') {
    const testDomain = req.query.domain || 'google.com';
    return testRDAP(testDomain, res);
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let domain = ((req.body && (req.body.domain || req.body.d)) || '').trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Dominio inválido' });

  return testRDAP(domain, res);
};

async function testRDAP(domain, res) {
  const result = { domain, timestamp: new Date().toISOString(), company: null, error: null };

  try {
    const tld = domain.split('.').pop();
    const rdapUrls = {
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
    };
    const url = rdapUrls[tld] ? rdapUrls[tld] + domain : `https://rdap.org/domain/${domain}`;

    const rdapData = await fetch(url);
    result.company = extractCompany(rdapData);

    if (rdapData.events) {
      const ev = (n) => { const e = rdapData.events.find(x => x.eventAction === n); return e ? e.eventDate : ''; };
      if (!result.company) result.company = {};
      result.company.creationDate = ev('registration');
      result.company.expiryDate = ev('expiration');
      result.company.registrar = (rdapData.port43 || '').replace('whois.', '').replace('.whois-servers.net', '');
      result.company.nameservers = (rdapData.nameservers || []).map(n => n.ldhName || n);
    }

    if (!result.company) result.error = 'No se encontraron datos de empresa en RDAP';

  } catch (e) {
    result.error = e.message;
  }

  res.json(result);
}

