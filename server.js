/**
 * InterviewAI Pro — Backend Server
 * Node.js 18+ required (uses built-in fetch, Blob, FormData)
 *
 * npm install express cors stripe dotenv
 * node server.js
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════════════════
//  CONFIG
// ════════════════════════════════════════════════════
const OPENAI_KEY          = process.env.OPENAI_API_KEY;
const ADMIN_KEY           = process.env.ADMIN_KEY;
const STRIPE_SECRET       = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SEC  = process.env.STRIPE_WEBHOOK_SECRET;
const FRONTEND_URL        = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

if (!OPENAI_KEY) { console.error('❌  Missing OPENAI_API_KEY in .env'); process.exit(1); }
if (!ADMIN_KEY)  { console.error('❌  Missing ADMIN_KEY in .env'); process.exit(1); }

let stripe = null;
if (STRIPE_SECRET) {
  stripe = require('stripe')(STRIPE_SECRET);
  console.log('✅  Stripe connected');
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set — payment endpoints disabled');
}

// ════════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════════
// Stripe webhook needs raw body BEFORE express.json()
app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json({ limit: '12mb' })); // room for base64 audio (~30s ≈ 4MB)
app.use(express.static(path.join(__dirname, 'public')));

// ════════════════════════════════════════════════════
//  LICENSE DATABASE  (JSON file — swap for Supabase/PostgreSQL at scale)
// ════════════════════════════════════════════════════
const DB_PATH = path.join(__dirname, 'licenses.json');

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8')); }
  catch { return {}; }
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

/**
 * Create a new license key.
 * @param {string} email   Customer email
 * @param {string} plan    'quarterly' | 'semiannual' | 'annual'
 * @returns {{ key: string, expiresAt: string }}
 */
function createLicense(email, plan) {
  const db = loadDB();
  const key = 'IAI-' + crypto.randomBytes(10).toString('hex').toUpperCase();
  const daysMap = { quarterly: 90, semiannual: 180, annual: 365 };
  const days = daysMap[plan] || 90;
  const expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
  db[key] = {
    email, plan, expiresAt,
    active: true,
    createdAt: new Date().toISOString(),
    stripeSessionId: null,
    usageCount: 0
  };
  saveDB(db);
  return { key, expiresAt };
}

/**
 * Check whether a license key is valid and not expired.
 * @returns {{ valid: boolean, reason?: string, lic?: object }}
 */
function checkLicense(key) {
  const db  = loadDB();
  const lic = db[key];
  if (!lic)        return { valid: false, reason: 'invalid' };
  if (!lic.active) return { valid: false, reason: 'revoked' };
  if (new Date(lic.expiresAt) < new Date())
    return { valid: false, reason: 'expired', expiresAt: lic.expiresAt };
  return { valid: true, lic };
}

function incrementUsage(key) {
  const db = loadDB();
  if (db[key]) { db[key].usageCount = (db[key].usageCount || 0) + 1; saveDB(db); }
}

// ════════════════════════════════════════════════════
//  SESSION STORE  (in-memory, 8-hour TTL)
// ════════════════════════════════════════════════════
/** @type {Map<string, { licenseKey: string, expiresAt: number }>} */
const sessions = new Map();

// Prune expired sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) if (s.expiresAt < now) sessions.delete(token);
}, 3_600_000);

function newSession(licenseKey) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { licenseKey, expiresAt: Date.now() + 8 * 3_600_000 });
  return token;
}

function resolveSession(token) {
  const s = sessions.get(token);
  if (!s || s.expiresAt < Date.now()) return null;
  const v = checkLicense(s.licenseKey);
  return v.valid ? s : null;
}

// ════════════════════════════════════════════════════
//  MIDDLEWARE HELPERS
// ════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  if (!resolveSession(req.headers['x-session']))
    return res.status(401).json({ error: 'Unauthorized — invalid or expired session' });
  next();
}

function requireAdmin(req, res, next) {
  if (req.headers['x-admin'] !== ADMIN_KEY)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════

/**
 * POST /api/login
 * Body: { key: "IAI-XXXXXX" }
 * Returns: { token, plan, email, expiresAt }
 */
app.post('/api/login', (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ error: 'License key required' });

  const v = checkLicense(key);
  if (!v.valid) {
    if (v.reason === 'expired')
      return res.status(402).json({ error: 'License expired', expiresAt: v.expiresAt });
    return res.status(401).json({ error: 'Invalid license key' });
  }

  const token = newSession(key);
  res.json({ token, plan: v.lic.plan, email: v.lic.email, expiresAt: v.lic.expiresAt });
});

/**
 * POST /api/checkout
 * Body: { plan: 'quarterly' | 'semiannual' | 'annual', email?: string }
 * Returns: { url: 'https://checkout.stripe.com/...' }
 */
app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured on server' });

  const { plan, email } = req.body;
  const prices = {
    quarterly:  process.env.STRIPE_PRICE_QUARTERLY,
    semiannual: process.env.STRIPE_PRICE_SEMIANNUAL,
    annual:     process.env.STRIPE_PRICE_ANNUAL
  };

  if (!prices[plan]) return res.status(400).json({ error: 'Invalid plan' });

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      customer_email: email || undefined,
      line_items: [{ price: prices[plan], quantity: 1 }],
      metadata: { plan },
      success_url: `${FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${FRONTEND_URL}/#pricing`,
      locale: 'pt-BR' // Portuguese checkout
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════
//  PROTECTED ROUTES  (require valid session)
// ════════════════════════════════════════════════════

/**
 * POST /api/transcribe
 * Body: { audio: "<base64>", mimeType: "audio/webm" }
 * Returns: { text: "..." }
 */
app.post('/api/transcribe', requireAuth, async (req, res) => {
  const { audio, mimeType } = req.body;
  if (!audio) return res.status(400).json({ error: 'No audio data' });

  try {
    const buffer = Buffer.from(audio, 'base64');
    const blob   = new Blob([buffer], { type: mimeType || 'audio/webm' });

    const fd = new FormData();
    fd.append('file', blob, 'audio.webm');
    fd.append('model', 'whisper-1');
    fd.append('language', 'en');

    const r    = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + OPENAI_KEY },
      body: fd
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || `Whisper HTTP ${r.status}`);
    res.json({ text: data.text?.trim() || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * POST /api/answer
 * Body: { question, profile, name?, style?, model? }
 * Returns: { answer: "..." }
 */
app.post('/api/answer', requireAuth, async (req, res) => {
  const { question, profile, name, style, model } = req.body;
  if (!question || !profile) return res.status(400).json({ error: 'question and profile required' });

  // Track usage
  const s = resolveSession(req.headers['x-session']);
  if (s) incrementUsage(s.licenseKey);

  const styleMap = {
    concise:  'Answer in 2-3 natural, confident sentences. Be direct.',
    detailed: 'Give a thorough answer in 4-6 sentences covering context, approach, and results.',
    star:     'Use the STAR method (Situation, Task, Action, Result). Keep it natural and conversational.',
    bullets:  'Answer with 3-4 bullet points starting with a dash (-).'
  };

  const system = `You are a real-time interview assistant.${name ? ` Candidate: ${name}.` : ''}

Candidate profile:
---
${profile}
---

Produce a strong, natural-sounding English answer the candidate can say live. Rules:
- Use ONLY experience from the profile above. Never fabricate.
- First-person voice ("I have…", "In my experience…").
- ${styleMap[style] || styleMap.concise}
- Respond with ONLY the answer text. No intro, no quotes around it.`;

  try {
    const r    = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
      body: JSON.stringify({
        model: model || 'gpt-4o-mini',
        messages: [{ role: 'system', content: system }, { role: 'user', content: question }],
        temperature: 0.7,
        max_tokens: 500
      })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || `GPT HTTP ${r.status}`);
    res.json({ answer: data.choices[0].message.content.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════
//  STRIPE WEBHOOK
// ════════════════════════════════════════════════════

/**
 * POST /stripe/webhook
 * Automatically creates a license when a payment is completed.
 * After creating the license key, send it by email (see TODO below).
 */
app.post('/stripe/webhook', async (req, res) => {
  if (!stripe) return res.status(503).send('Stripe not configured');

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SEC);
  } catch (e) {
    console.error('Webhook signature error:', e.message);
    return res.status(400).send('Webhook Error: ' + e.message);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_email || session.customer_details?.email;
    const plan    = session.metadata?.plan || 'quarterly';

    if (email) {
      const { key, expiresAt } = createLicense(email, plan);

      // Update Stripe session ID for reference
      const db = loadDB();
      if (db[key]) { db[key].stripeSessionId = session.id; saveDB(db); }

      console.log(`✅ License created — ${email} | ${plan} | Key: ${key} | Expires: ${expiresAt}`);

      // ─────────────────────────────────────────────────
      // TODO: Send license key by email using Resend or SendGrid
      //
      // Example with Resend (npm install resend):
      //   const { Resend } = require('resend');
      //   const resend = new Resend(process.env.RESEND_API_KEY);
      //   await resend.emails.send({
      //     from: 'InterviewAI Pro <noreply@yourdomain.com>',
      //     to: email,
      //     subject: 'Your InterviewAI Pro license key',
      //     html: `<h2>Welcome!</h2>
      //            <p>Your license key: <strong>${key}</strong></p>
      //            <p>Plan: ${plan} | Expires: ${new Date(expiresAt).toLocaleDateString()}</p>
      //            <p><a href="${FRONTEND_URL}/app.html">Access the app →</a></p>`
      //   });
      // ─────────────────────────────────────────────────
    }
  }

  res.json({ received: true });
});

// ════════════════════════════════════════════════════
//  ADMIN ROUTES  (protected by x-admin header)
// ════════════════════════════════════════════════════

// Create license manually (for test users, free trials, etc.)
app.post('/admin/license/create', requireAdmin, (req, res) => {
  const { email, plan } = req.body;
  if (!email || !plan) return res.status(400).json({ error: 'email and plan required' });
  const result = createLicense(email, plan);
  res.json(result);
});

// List all licenses
app.get('/admin/licenses', requireAdmin, (req, res) => {
  const db = loadDB();
  // Sort by createdAt descending
  const list = Object.entries(db)
    .map(([key, lic]) => ({ key, ...lic }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// Revoke a license immediately
app.post('/admin/license/revoke', requireAdmin, (req, res) => {
  const key = (req.body.key || '').toUpperCase();
  const db  = loadDB();
  if (!db[key]) return res.status(404).json({ error: 'License not found' });
  db[key].active = false;
  saveDB(db);
  res.json({ revoked: true, key });
});

// Extend a license
app.post('/admin/license/extend', requireAdmin, (req, res) => {
  const key  = (req.body.key || '').toUpperCase();
  const days = parseInt(req.body.days) || 30;
  const db   = loadDB();
  if (!db[key]) return res.status(404).json({ error: 'License not found' });
  const current = new Date(db[key].expiresAt) > new Date() ? new Date(db[key].expiresAt) : new Date();
  current.setDate(current.getDate() + days);
  db[key].expiresAt = current.toISOString();
  db[key].active = true;
  saveDB(db);
  res.json({ extended: true, key, newExpiry: db[key].expiresAt });
});

// ════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║    InterviewAI Pro — Backend         ║
  ║    http://localhost:${PORT}              ║
  ╚══════════════════════════════════════╝
  `);
});
