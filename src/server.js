import express from 'express';
import crypto from 'node:crypto';
import pkg from 'whatsapp-web.js';
import QRCode from 'qrcode';

const { Client, LocalAuth } = pkg;

const PORT = process.env.PORT || 8080;
const SECRET = process.env.WA_BRIDGE_SECRET;
const WEBHOOK_URL = process.env.SUPABASE_WEBHOOK_URL;
const SESSION_DIR = process.env.WA_SESSION_DIR || '/data/.wwebjs_auth';

if (!SECRET) {
  console.error('WA_BRIDGE_SECRET is required');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------- HMAC verification ----------
function verifyHmac(req, res, next) {
  const sig = req.header('x-bridge-signature');
  const ts = req.header('x-bridge-timestamp');
  if (!sig || !ts) return res.status(401).json({ error: 'missing signature' });

  const age = Math.abs(Date.now() - Number(ts));
  if (age > 5 * 60 * 1000) return res.status(401).json({ error: 'stale timestamp' });

  const body = JSON.stringify(req.body || {});
  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(`${ts}.${body}`)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(401).json({ error: 'bad signature' });
  }

  next();
}

function signOutgoing(body) {
  const ts = Date.now().toString();
  const sig = crypto
    .createHmac('sha256', SECRET)
    .update(`${ts}.${JSON.stringify(body)}`)
    .digest('hex');
  return { ts, sig };
}

// ---------- Multi-tenant client manager ----------
const clients = new Map(); // clinicId -> { client, status, qr, phone }

async function postToSupabase(payload) {
  if (!WEBHOOK_URL) return;
  const { ts, sig } = signOutgoing(payload);
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-bridge-signature': sig,
        'x-bridge-timestamp': ts,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('webhook post failed', err);
  }
}

function getOrCreate(clinicId) {
  let entry = clients.get(clinicId);
  if (entry) return entry;

  const client = new Client({
    authStrategy: new LocalAuth({ clientId: clinicId, dataPath: '/data/.wwebjs_auth' }),
    puppeteer: {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--single-process',
      ],
      protocolTimeout: 120000, // 120s — fixes "Runtime.callFunctionOn timed out"
    },
  });

  entry = { client, status: 'disconnected', qr: null, phone: null };
  clients.set(clinicId, entry);

  client.on('qr', async (qr) => {
    entry.status = 'qr_pending';
    entry.qr = await QRCode.toDataURL(qr);
    postToSupabase({ event: 'qr', clinicId, status: entry.status });
  });

  client.on('authenticated', () => {
    entry.status = 'authenticated';
    postToSupabase({ event: 'authenticated', clinicId, status: entry.status });
  });

  client.on('ready', () => {
    entry.status = 'ready';
    entry.qr = null;
    entry.phone = client.info?.wid?.user || null;
    postToSupabase({ event: 'ready', clinicId, status: 'ready', phone: entry.phone });
  });

  client.on('disconnected', (reason) => {
    entry.status = 'disconnected';
    entry.qr = null;
    postToSupabase({ event: 'disconnected', clinicId, reason });
  });

  client.on('message', (msg) => {
    postToSupabase({
      event: 'message',
      clinicId,
      from: msg.from,
      to: msg.to,
      body: msg.body,
      messageId: msg.id?._serialized,
      timestamp: msg.timestamp,
      fromMe: msg.fromMe,
    });
  });

  client.on('message_ack', (msg, ack) => {
    postToSupabase({
      event: 'message_ack',
      clinicId,
      messageId: msg.id?._serialized,
      ack, // 1=sent, 2=received, 3=read, 4=played
    });
  });

  return entry;
}

// ---------- Routes ----------
app.get('/healthz', (_req, res) => res.json({ ok: true, clinics: clients.size }));

app.post('/sessions/:clinicId/start', verifyHmac, async (req, res) => {
  const { clinicId } = req.params;
  const entry = getOrCreate(clinicId);
  if (entry.status === 'disconnected') {
    entry.client.initialize().catch((err) => {
      console.error('init failed', clinicId, err);
      entry.status = 'disconnected';
    });
    entry.status = 'qr_pending';
  }
  res.json({ status: entry.status, qr: entry.qr, phone: entry.phone });
});

app.get('/sessions/:clinicId/status', verifyHmac, (req, res) => {
  const entry = clients.get(req.params.clinicId);
  if (!entry) return res.json({ status: 'disconnected', qr: null, phone: null });
  res.json({ status: entry.status, qr: entry.qr, phone: entry.phone });
});

app.post('/sessions/:clinicId/logout', verifyHmac, async (req, res) => {
  const entry = clients.get(req.params.clinicId);
  if (entry) {
    try { await entry.client.logout(); } catch {}
    try { await entry.client.destroy(); } catch {}
    clients.delete(req.params.clinicId);
  }
  res.json({ ok: true });
});

app.post('/sessions/:clinicId/send', verifyHmac, async (req, res) => {
  const { clinicId } = req.params;
  const { to, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message required' });

  const entry = clients.get(clinicId);
  if (!entry || entry.status !== 'ready') {
    return res.status(409).json({ error: 'session_not_ready', status: entry?.status || 'disconnected' });
  }

  // Normalize to WhatsApp JID
  const digits = String(to).replace(/[^\d]/g, '');
  const jid = digits.includes('@') ? to : `${digits}@c.us`;

  try {
    const sent = await entry.client.sendMessage(jid, message);
    res.json({ ok: true, messageId: sent.id?._serialized });
  } catch (err) {
    console.error('send failed', err);
    res.status(500).json({ error: 'send_failed', detail: String(err?.message || err) });
  }
});

app.listen(PORT, () => {
  console.log(`whatsapp-bridge listening on :${PORT}`);
});
