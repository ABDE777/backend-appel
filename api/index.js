'use strict';

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

// ─── Environment ─────────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 3000;

// Fail fast if critical env vars are missing
if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error('[FATAL] SUPABASE_URL ou SUPABASE_SECRET_KEY manquant dans .env');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('[FATAL] JWT_SECRET manquant dans .env');
  process.exit(1);
}

// ─── Supabase client (service role — ne jamais exposer côté client) ───────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

// ─── App setup ────────────────────────────────────────────────────────────────
const app = express();

// CORS — autorise toutes les origines (Netlify, Vercel, localhost)
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '1mb' }));

// ─── Simple in-memory rate limiter (pas de dépendance externe) ────────────────
const rateLimitStore = new Map();
function rateLimit({ windowMs = 60_000, max = 20 } = {}) {
  return (req, res, next) => {
    const key = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const now = Date.now();
    const record = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > record.resetAt) {
      record.count = 0;
      record.resetAt = now + windowMs;
    }
    record.count++;
    rateLimitStore.set(key, record);

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - record.count));

    if (record.count > max) {
      return res.status(429).json({ error: 'Trop de requêtes. Réessayez dans quelques instants.' });
    }
    next();
  };
}

// Nettoyage périodique du store (évite les fuites mémoire sur Vercel serverless)
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitStore) {
    if (now > val.resetAt) rateLimitStore.delete(key);
  }
}, 60_000);

// ─── Security headers ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Pas de cache sur les routes d'API sensibles
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});

// ─── JWT helpers ──────────────────────────────────────────────────────────────
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.slice(7);
  if (!token) return res.status(401).json({ error: 'Authentification requise' });

  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Session expirée' : 'Token invalide';
    return res.status(403).json({ error: msg });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role === 'admin') return next();
  return res.status(403).json({ error: 'Accès réservé aux administrateurs' });
}

// ─── Input sanitizers ─────────────────────────────────────────────────────────
function sanitizeText(val, maxLen = 100) {
  if (typeof val !== 'string') return null;
  return val.trim().slice(0, maxLen) || null;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────
async function verifyPassword(plain, stored) {
  if (!plain || !stored) return false;
  // Mot de passe haché bcrypt
  if (stored.startsWith('$2a$') || stored.startsWith('$2b$')) {
    return bcrypt.compareSync(plain, stored);
  }
  // Mot de passe en clair — vérifier puis upgrader vers bcrypt
  return plain === stored;
}

async function upgradePasswordIfNeeded(table, name, plainPassword, storedHash) {
  if (!storedHash.startsWith('$2a$') && !storedHash.startsWith('$2b$')) {
    const hashed = bcrypt.hashSync(plainPassword, 12);
    await supabase.from(table).update({ password: hashed }).eq('name', name);
  }
}

// ─── Router ───────────────────────────────────────────────────────────────────
const router = express.Router();

// GET /status — Health check (public)
router.get('/status', async (req, res) => {
  try {
    const { error } = await supabase.from('agents').select('name').limit(1);
    if (error) throw error;
    return res.json({ status: 'online', dbConnected: true, ts: new Date().toISOString() });
  } catch (err) {
    return res.json({ status: 'online', dbConnected: false, error: err.message, ts: new Date().toISOString() });
  }
});

// GET /auth/users — Liste des noms pour le dropdown login (public, noms seulement)
router.get('/auth/users', async (req, res) => {
  try {
    const [{ data: agentsData }, { data: adminsData }] = await Promise.all([
      supabase.from('agents').select('name').order('name', { ascending: true }),
      supabase.from('admins').select('name').order('name', { ascending: true }),
    ]);

    const users = [];
    const seen = new Set();

    (adminsData || []).forEach(a => {
      if (!seen.has(a.name.toLowerCase())) {
        seen.add(a.name.toLowerCase());
        users.push({ name: a.name, role: 'admin' });
      }
    });
    (agentsData || []).forEach(a => {
      if (!seen.has(a.name.toLowerCase())) {
        seen.add(a.name.toLowerCase());
        users.push({ name: a.name, role: 'agent' });
      }
    });

    return res.json(users);
  } catch (err) {
    console.error('[GET /auth/users]', err.message);
    return res.status(500).json({ error: 'Impossible de charger les utilisateurs' });
  }
});

// POST /auth/login — Connexion unifiée avec rate limit strict
router.post('/auth/login', rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  const name = sanitizeText(req.body?.name, 80);
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;

  if (!name || !password) {
    return res.status(400).json({ success: false, message: 'Nom et mot de passe requis' });
  }

  try {
    // 1. Chercher dans la table admins
    const { data: adminRow, error: adminErr } = await supabase
      .from('admins')
      .select('name, password')
      .ilike('name', name)   // insensible à la casse
      .limit(1)
      .maybeSingle();

    if (!adminErr && adminRow) {
      const valid = await verifyPassword(password, adminRow.password);
      if (valid) {
        await upgradePasswordIfNeeded('admins', adminRow.name, password, adminRow.password);
        const token = generateToken({ role: 'admin', name: adminRow.name });
        return res.json({ success: true, name: adminRow.name, role: 'admin', token });
      }
      // Nom trouvé mais mauvais mot de passe → réponse immédiate (pas de fallback sur agents)
      return res.status(401).json({ success: false, message: 'Mot de passe incorrect' });
    }

    // 2. Chercher dans la table agents
    const { data: agentRow, error: agentErr } = await supabase
      .from('agents')
      .select('name, password')
      .ilike('name', name)
      .limit(1)
      .maybeSingle();

    if (!agentErr && agentRow) {
      const valid = await verifyPassword(password, agentRow.password);
      if (valid) {
        await upgradePasswordIfNeeded('agents', agentRow.name, password, agentRow.password);
        const token = generateToken({ role: 'agent', name: agentRow.name });
        return res.json({ success: true, name: agentRow.name, role: 'agent', token });
      }
      return res.status(401).json({ success: false, message: 'Mot de passe incorrect' });
    }

    return res.status(401).json({ success: false, message: 'Utilisateur introuvable' });
  } catch (err) {
    console.error('[POST /auth/login]', err.message);
    return res.status(500).json({ error: 'Erreur serveur lors de la connexion' });
  }
});

// GET /entries — Lister tous les appels (authentifié)
router.get('/entries', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('entries')
      .select('id, ref, motif_id, caller_type, comment, agent, date, time, ts')
      .order('ts', { ascending: false })
      .limit(5000);

    if (error) throw error;

    return res.json((data || []).map(e => ({
      id: e.id,
      ref: e.ref || '',
      motifId: e.motif_id,
      callerType: e.caller_type || null,
      comment: e.comment || null,
      agent: e.agent,
      date: e.date,
      time: e.time,
      ts: e.ts,
    })));
  } catch (err) {
    console.error('[GET /entries]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// POST /entries — Créer un appel (authentifié)
router.post('/entries', authenticateToken, async (req, res) => {
  const body = req.body;

  // Validation
  const motifId = sanitizeText(body?.motifId, 60);
  const agent = sanitizeText(body?.agent, 80);
  if (!motifId || !agent) {
    return res.status(400).json({ error: 'motifId et agent sont requis' });
  }

  // Sécurité : un agent ne peut soumettre que pour lui-même
  if (req.user.role === 'agent' && agent !== req.user.name) {
    return res.status(403).json({ error: 'Vous ne pouvez soumettre que pour votre propre compte' });
  }

  const id = sanitizeText(body.id, 32) || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7));
  const now = new Date();

  const row = {
    id,
    ref: sanitizeText(body.ref, 20) || '',
    motif_id: motifId,
    caller_type: ['client', 'agent'].includes(body.callerType) ? body.callerType : null,
    comment: sanitizeText(body.comment, 500),
    agent,
    date: sanitizeText(body.date, 10) || now.toISOString().slice(0, 10),
    time: sanitizeText(body.time, 5) || now.toTimeString().slice(0, 5),
    ts: body.ts || now.toISOString(),
  };

  try {
    const { error } = await supabase.from('entries').upsert(row, { onConflict: 'id' });
    if (error) throw error;
    return res.status(201).json({ success: true, entry: { ...row, motifId: row.motif_id, callerType: row.caller_type } });
  } catch (err) {
    console.error('[POST /entries]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// PUT /entries/:id — Modifier un appel codifié (authentifié)
router.put('/entries/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const body = req.body;
  if (!id) return res.status(400).json({ error: 'ID requis' });

  try {
    const { data: existing, error: getErr } = await supabase
      .from('entries')
      .select('agent')
      .eq('id', id)
      .maybeSingle();

    if (getErr) throw getErr;
    if (!existing) return res.status(404).json({ error: 'Appel non trouvé' });

    if (req.user.role === 'agent' && existing.agent !== req.user.name) {
      return res.status(403).json({ error: 'Vous ne pouvez modifier que vos propres codifications' });
    }

    const updateData = {};
    if (body.ref !== undefined) updateData.ref = sanitizeText(body.ref, 20) || '';
    if (body.motifId) updateData.motif_id = sanitizeText(body.motifId, 60);
    if (body.callerType !== undefined) updateData.caller_type = ['client', 'agent'].includes(body.callerType) ? body.callerType : null;
    if (body.comment !== undefined) updateData.comment = sanitizeText(body.comment, 500);

    const { error } = await supabase.from('entries').update(updateData).eq('id', id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    console.error('[PUT /entries/:id]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// POST /entries/batch — Import en masse (admin seulement)
router.post('/entries/batch', authenticateToken, requireAdmin, async (req, res) => {
  const { entries } = req.body;
  if (!Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ error: "Tableau 'entries' requis et non vide" });
  }
  if (entries.length > 1000) {
    return res.status(400).json({ error: 'Maximum 1000 entrées par batch' });
  }

  const now = new Date();
  const rows = entries.map(e => ({
    id: sanitizeText(e.id, 32) || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7)),
    ref: sanitizeText(e.ref, 20) || '',
    motif_id: sanitizeText(e.motifId, 60),
    caller_type: ['client', 'agent'].includes(e.callerType) ? e.callerType : null,
    comment: sanitizeText(e.comment, 500),
    agent: sanitizeText(e.agent, 80),
    date: sanitizeText(e.date, 10) || now.toISOString().slice(0, 10),
    time: sanitizeText(e.time, 5) || now.toTimeString().slice(0, 5),
    ts: e.ts || now.toISOString(),
  }));

  try {
    const { error } = await supabase.from('entries').upsert(rows, { onConflict: 'id' });
    if (error) throw error;
    return res.json({ success: true, count: rows.length });
  } catch (err) {
    console.error('[POST /entries/batch]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// GET /agents — Liste des agents (admin seulement, sans mots de passe)
router.get('/agents', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('agents').select('name').order('name');
    if (error) throw error;
    return res.json((data || []).map(a => ({ name: a.name, password: '********' })));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /agents — Créer un agent (admin seulement)
router.post('/agents', authenticateToken, requireAdmin, async (req, res) => {
  const name = sanitizeText(req.body?.name, 80);
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;

  if (!name || !password) {
    return res.status(400).json({ error: 'Nom et mot de passe requis' });
  }

  try {
    const hashed = bcrypt.hashSync(password, 12);
    const { error } = await supabase
      .from('agents')
      .upsert({ name, password: hashed }, { onConflict: 'name' });
    if (error) throw error;
    return res.status(201).json({ success: true, name });
  } catch (err) {
    console.error('[POST /agents]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /agents/:name — Supprimer un agent (admin seulement)
router.delete('/agents/:name', authenticateToken, requireAdmin, async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  try {
    const { error } = await supabase.from('agents').delete().eq('name', name);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// PUT /agents/:name — Modifier un agent (mot de passe et/ou nom) (admin seulement)
router.put('/agents/:name', authenticateToken, requireAdmin, async (req, res) => {
  const oldName = decodeURIComponent(req.params.name);
  const newName = sanitizeText(req.body?.name, 80) || oldName;
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;

  try {
    const updateData = {};
    if (newName && newName !== oldName) updateData.name = newName;
    if (password && password.trim() !== "") updateData.password = bcrypt.hashSync(password, 12);

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'Aucune modification transmise' });
    }

    const { error } = await supabase
      .from('agents')
      .update(updateData)
      .eq('name', oldName);

    if (error) throw error;

    // Si le nom a changé, mettre à jour toutes les entrées enregistrées par cet agent
    if (newName && newName !== oldName) {
      await supabase
        .from('entries')
        .update({ agent: newName })
        .eq('agent', oldName);
    }

    return res.json({ success: true, name: newName });
  } catch (err) {
    console.error('[PUT /agents/:name]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// GET /admins — Liste des admins (admin seulement, sans mots de passe)
router.get('/admins', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('name').order('name');
    if (error) throw error;
    return res.json((data || []).map(a => ({ name: a.name, password: '********' })));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /admins — Créer un admin (admin seulement)
router.post('/admins', authenticateToken, requireAdmin, async (req, res) => {
  const name = sanitizeText(req.body?.name, 80);
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;

  if (!name || !password) {
    return res.status(400).json({ error: 'Nom et mot de passe requis' });
  }

  try {
    const hashed = bcrypt.hashSync(password, 12);
    const { error } = await supabase
      .from('admins')
      .upsert({ name, password: hashed }, { onConflict: 'name' });
    if (error) throw error;
    return res.status(201).json({ success: true, name });
  } catch (err) {
    console.error('[POST /admins]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /admins/:name — Supprimer un admin (admin seulement)
router.delete('/admins/:name', authenticateToken, requireAdmin, async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  // Sécurité : empêcher un admin de se supprimer lui-même
  if (name === req.user.name) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }
  try {
    const { error } = await supabase.from('admins').delete().eq('name', name);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// PUT /admins/:name — Modifier un admin (mot de passe et/ou nom) (admin seulement)
router.put('/admins/:name', authenticateToken, requireAdmin, async (req, res) => {
  const oldName = decodeURIComponent(req.params.name);
  const newName = sanitizeText(req.body?.name, 80) || oldName;
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;

  try {
    const updateData = {};
    if (newName && newName !== oldName) updateData.name = newName;
    if (password && password.trim() !== "") updateData.password = bcrypt.hashSync(password, 12);

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'Aucune modification transmise' });
    }

    const { error } = await supabase
      .from('admins')
      .update(updateData)
      .eq('name', oldName);

    if (error) throw error;

    // Si le nom a changé, mettre à jour toutes les entrées enregistrées par cet admin
    if (newName && newName !== oldName) {
      await supabase
        .from('entries')
        .update({ agent: newName })
        .eq('agent', oldName);
    }

    return res.json({ success: true, name: newName });
  } catch (err) {
    console.error('[PUT /admins/:name]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// GET /notes — Notes internes (admin seulement)
router.get('/notes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('notes').select('id, data');
    if (error) throw error;

    const notes = { refs: {}, agents: {} };
    (data || []).forEach(row => {
      if (row.id === 'refs') notes.refs = row.data || {};
      if (row.id === 'agents') notes.agents = row.data || {};
    });
    return res.json(notes);
  } catch (err) {
    return res.json({ refs: {}, agents: {} });
  }
});

// POST /notes — Sauvegarder les notes (admin seulement)
router.post('/notes', authenticateToken, requireAdmin, async (req, res) => {
  const refs = req.body?.refs || {};
  const agents = req.body?.agents || {};

  try {
    const { error } = await supabase.from('notes').upsert(
      [{ id: 'refs', data: refs }, { id: 'agents', data: agents }],
      { onConflict: 'id' }
    );
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /settings — Paramètres (authentifié)
router.get('/settings', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('value')
      .eq('key', 'threshold')
      .maybeSingle();

    if (error) throw error;
    return res.json({ threshold: data ? (parseInt(data.value) || 3) : 3 });
  } catch (err) {
    return res.json({ threshold: 3 });
  }
});

// POST /settings — Modifier paramètres (admin seulement)
router.post('/settings', authenticateToken, requireAdmin, async (req, res) => {
  let threshold = parseInt(req.body?.threshold);
  if (isNaN(threshold) || threshold < 2 || threshold > 20) {
    return res.status(400).json({ error: 'threshold doit être entre 2 et 20' });
  }

  try {
    const { error } = await supabase
      .from('settings')
      .upsert({ key: 'threshold', value: String(threshold) }, { onConflict: 'key' });
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /agents/import — Import en masse depuis CSV/Excel (admin seulement)
// Body: { names: ["alice","bob",...], role: "agent"|"admin" }
router.post('/agents/import', authenticateToken, requireAdmin, async (req, res) => {
  const names = req.body?.names;
  const role = req.body?.role === 'admin' ? 'admin' : 'agent';
  if (!Array.isArray(names) || names.length === 0) {
    return res.status(400).json({ error: 'Liste de noms requise' });
  }

  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const results = [];
  const mustChangeNames = [];

  for (let i = 0; i < names.length; i++) {
    const name = sanitizeText(String(names[i]).trim(), 80);
    if (!name) continue;
    const id = String(i + 1).padStart(3, '0');
    const plainPassword = `${name.toLowerCase()}${id}${hh}${mm}`;
    const hashed = bcrypt.hashSync(plainPassword, 12);
    const table = role === 'admin' ? 'admins' : 'agents';
    try {
      const { error } = await supabase.from(table).upsert({ name, password: hashed }, { onConflict: 'name' });
      if (!error) {
        results.push({ name, password: plainPassword, role });
        mustChangeNames.push(name);
      }
    } catch (e) {
      console.error(`[import] ${name}:`, e.message);
    }
  }

  // Stocker la liste must_change_password dans settings
  try {
    const { data: existing } = await supabase.from('settings').select('value').eq('key', 'must_change_password').maybeSingle();
    const existingList = existing ? JSON.parse(existing.value || '[]') : [];
    const merged = [...new Set([...existingList, ...mustChangeNames])];
    await supabase.from('settings').upsert({ key: 'must_change_password', value: JSON.stringify(merged) }, { onConflict: 'key' });
  } catch (e) {}

  return res.json({ success: true, created: results });
});

// GET /user/must-change — Vérifier si l'utilisateur connecté doit changer son mot de passe
router.get('/user/must-change', authenticateToken, async (req, res) => {
  try {
    const { data } = await supabase.from('settings').select('value').eq('key', 'must_change_password').maybeSingle();
    const list = data ? JSON.parse(data.value || '[]') : [];
    return res.json({ mustChange: list.includes(req.user.name) });
  } catch (err) {
    return res.json({ mustChange: false });
  }
});

// POST /user/change-password — Changer son propre mot de passe
router.post('/user/change-password', authenticateToken, async (req, res) => {
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : null;
  if (!password || password.trim().length < 4) {
    return res.status(400).json({ error: 'Mot de passe trop court (minimum 4 caractères)' });
  }
  const hashed = bcrypt.hashSync(password, 12);
  const table = req.user.role === 'admin' ? 'admins' : 'agents';
  try {
    const { error } = await supabase.from(table).update({ password: hashed }).eq('name', req.user.name);
    if (error) throw error;
    // Retirer de la liste must_change
    const { data } = await supabase.from('settings').select('value').eq('key', 'must_change_password').maybeSingle();
    if (data) {
      const list = JSON.parse(data.value || '[]').filter(n => n !== req.user.name);
      await supabase.from('settings').upsert({ key: 'must_change_password', value: JSON.stringify(list) }, { onConflict: 'key' });
    }
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /notes — Récupérer toutes les notes (admins seulement)
router.get('/notes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('value')
      .eq('key', 'notes')
      .maybeSingle();

    if (error) throw error;
    if (!data || !data.value) {
      return res.json({ refs: {}, agents: {} });
    }
    const notes = JSON.parse(data.value);
    return res.json({ refs: notes.refs || {}, agents: notes.agents || {} });
  } catch (err) {
    return res.json({ refs: {}, agents: {} });
  }
});

// POST /notes — Sauvegarder les notes (admins seulement)
router.post('/notes', authenticateToken, requireAdmin, async (req, res) => {
  const notes = req.body;
  if (!notes || typeof notes !== 'object') {
    return res.status(400).json({ error: 'Corps de requête invalide' });
  }

  const payload = {
    refs: notes.refs || {},
    agents: notes.agents || {}
  };

  try {
    const { error } = await supabase
      .from('settings')
      .upsert({ key: 'notes', value: JSON.stringify(payload) }, { onConflict: 'key' });
    if (error) throw error;
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── 404 catch-all ────────────────────────────────────────────────────────────
router.use((req, res) => {
  res.status(404).json({ error: `Route introuvable : ${req.method} ${req.path}` });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Unhandled Error]', err.message);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

// ─── Mount router ─────────────────────────────────────────────────────────────
// Toutes les routes sont sous /api (Vercel et Netlify proxy)
app.use('/api', router);

// Compatibilité Vercel (les rewrites mappent / → /api)
app.use('/', router);

// ─── Export pour Vercel (serverless) ─────────────────────────────────────────
module.exports = app;

// ─── Dev server local ─────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
    console.log(`   ENV : ${NODE_ENV}`);
    console.log(`   DB  : ${SUPABASE_URL}\n`);
  });
}
