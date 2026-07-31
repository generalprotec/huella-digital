const net = require('net');

const TLD_SERVERS = { es: 'whois.nic.es' };

const OTI_HOST = 'domain-intelligence-api.p.rapidapi.com';
const OTI_KEY = process.env.RAPIDAPI_KEY || '';

async function otiWhois(domain) {
  if (!OTI_KEY) return null;
  const url = 'https://' + OTI_HOST + '/domain/' + encodeURIComponent(domain) + '/whois';
  const r = await fetch(url, {
    headers: {
      'X-RapidAPI-Host': OTI_HOST,
      'X-RapidAPI-Key': OTI_KEY,
      Accept: 'application/json'
    },
    signal: AbortSignal.timeout(15000)
  });
  return await r.json();
}

function fromOti(j, domain, tld) {
  const has = !!(j && (j.ldhName || j.created || j.expires || j.registrar ||
    (Array.isArray(j.nameservers) && j.nameservers.length)));
  const data = {
    found: has,
    org: '', name: '', email: '', phone: '', address: '',
    created: (j && j.created) || '',
    expires: (j && j.expires) || '',
    registrar: (j && j.registrar) || '',
    nameservers: (j && Array.isArray(j.nameservers)) ? j.nameservers : [],
    domain: domain,
    tld: tld,
    server: (j && j._source) || 'OTI Labs (RapidAPI)',
    source: 'OTI Labs (RapidAPI)',
    raw: JSON.stringify(j || {}, null, 2)
  };
  if (!has) data.error = 'sin datos';
  return data;
}

function whois(server, query, timeout) {
  return new Promise((resolve, reject) => {
    let sock;
    try {
      sock = net.connect(43, server);
    } catch (e) {
      return reject(e);
    }
    let buf = '';
    const finish = (err) => {
      try { sock.destroy(); } catch (_) {}
      if (err) reject(err); else resolve(buf);
    };
    const timer = setTimeout(() => finish(new Error('timeout ' + server)), timeout);
    sock.on('connect', () => sock.write(query + '\r\n'));
    sock.on('data', (d) => { buf += d.toString('utf8'); });
    sock.on('error', (e) => { clearTimeout(timer); finish(e); });
    sock.on('close', () => { clearTimeout(timer); finish(); });
  });
}

async function resolveServer(tld) {
  if (TLD_SERVERS[tld]) return TLD_SERVERS[tld];
  try {
    const raw = await whois('whois.iana.org', tld.toUpperCase(), 7000);
    const m = raw.match(/whois:\s*(\S+)/i);
    if (m) return m[1];
  } catch (_) {}
  return null;
}

const clean = (v) => (v || '').trim();

function parse(raw) {
  const res = {
    found: false, org: '', name: '', email: '', phone: '', address: '',
    created: '', expires: '', registrar: '', nameservers: []
  };
  const blocked = /(not authorised|not authorized|is not authorised|ip address[^\r\n]*not[^\r\n]*authoris|request access to the service)/i;
  if (blocked.test(raw)) {
    res.error = 'el registro exige IP autorizada';
    return res;
  }
  const notFound = /(^|\r?\n)\s*%?\s*(no entries found|no match for|not found|no data found|no matching record|the queried object does not exist|object does not exist|is not registered|domain not found|no such domain|not been registered|no registrado|no existe|does not exist)\b/i;
  if (notFound.test(raw)) return res;
  res.found = true;

  const pick = (re) => { const m = raw.match(re); return m ? clean(m[1]) : ''; };
  res.created = pick(/Registered(?:\s*on)?:\s*([^\r\n]+)/i);
  res.expires = pick(/Expiration(?:\s*date)?:\s*([^\r\n]+)/i);
  res.registrar = pick(/Registrar:\s*([^\r\n]+)/i);

  const nsBlock = raw.match(/Nameservers:([\s\S]*?)(?=\n\s*\n|\n[A-Z][A-Za-z ]+:|$)/i);
  if (nsBlock) {
    res.nameservers = nsBlock[1].split(/[\s,;]+/).map(clean).filter((x) => x && !/^nameserver/i.test(x));
  }

  let block = '';
  const sec = raw.split(/\n\s*Registrant\s*:\s*\n/i)[1];
  if (sec) {
    block = sec.split(/\n\s*\n/)[0];
  } else {
    const sec2 = raw.match(/Registrant:([\s\S]*?)(?=\n\s*\n|\n[A-Z][A-Za-z ]+:|$)/i);
    if (sec2) block = sec2[1];
  }

  const label = (name) => {
    const re = new RegExp('(?:^|\\r?\\n)\\s*' + name + '\\b\\s*[:.]?\\s*([^\\r\\n]+)', 'i');
    const m = block.match(re) || raw.match(re);
    return m ? clean(m[1]) : '';
  };

  res.name = label('Name');
  res.org = label('Organization') || label('Organisation') || label('Company') ||
            label('Company name') || label('Empresa') || label('Registrant name') ||
            label('Titular') || label('Domain owner') || label('Organisation name');
  res.email = label('E-mail') || label('Email') || label('e-mail');
  res.phone = label('Phone') || label('Tel') || label('Teléfono');
  res.address = [label('Address'), label('City'), label('Postal'), label('Province'), label('Country')]
    .map(clean).filter(Boolean).join(', ');

  if (!res.org && !res.name) {
    const lines = block.split('\n').map(clean).filter(Boolean);
    if (lines.length) res.org = lines[0];
  }
  return res;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  const { searchParams } = new URL(req.url, 'http://localhost');
  const domain = String(searchParams.get('domain') || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) {
    return res.status(400).json({ domain, found: false, error: 'invalid domain' });
  }
  const tld = domain.split('.').pop();
  try {
    const server = await resolveServer(tld);
    if (!server) {
      return res.json({ domain, found: false, error: 'no whois server for .' + tld });
    }
    const raw = await whois(server, domain, 9000);
    const data = parse(raw);
    data.domain = domain;
    data.tld = tld;
    data.server = server;
    data.raw = raw.slice(0, 4000);
    const directFailed = (!data.found && (data.error || !raw.trim()));
    if (directFailed && tld !== 'es') {
      const alt = await otiWhois(domain);
      if (alt && !alt.error) {
        const mapped = fromOti(alt, domain, tld);
        if (mapped.found) return res.json(mapped);
      }
    }
    res.json(data);
  } catch (e) {
    if (tld !== 'es') {
      const alt = await otiWhois(domain);
      if (alt && !alt.error) return res.json(fromOti(alt, domain, tld));
    }
    res.status(502).json({ domain, found: false, error: String((e && e.message) || e) });
  }
};
