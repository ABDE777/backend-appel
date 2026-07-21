const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// Connection String PostgreSQL Supabase & mot de passe admin
// NOTE: Use port 6543 (pooler) for serverless environments like Vercel
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Sinistre2026";

if (!DATABASE_URL) {
  console.error("CRITICAL: DATABASE_URL environment variable is not set!");
}

// Initialisation du pool de connexions PostgreSQL
let pool = null;
if (DATABASE_URL) {
  try {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 3,                    // Keep low for serverless
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    });
    pool.on('error', (err) => {
      console.error('PostgreSQL pool error:', err.message);
    });
  } catch (err) {
    console.error("Erreur d'initialisation du Pool PostgreSQL:", err);
  }
}

// Routeur principal
const router = express.Router();

// GET /status (ou /api/status)
router.get('/status', async (req, res) => {
  if (!pool) {
    return res.json({ status: 'online', dbConnected: false, message: 'DATABASE_URL non configurée' });
  }
  try {
    const client = await pool.connect();
    client.release();
    return res.json({
      status: 'online',
      dbConnected: true,
      driver: 'PostgreSQL (pg Pool)',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    return res.json({
      status: 'online',
      dbConnected: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Auth Admin
router.post('/auth/admin', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false, message: "Mot de passe incorrect" });
});

// Auth Conseiller
router.post('/auth/agent', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ success: false, message: "Identifiants manquants" });
  if (!pool) return res.status(500).json({ error: "Base de données non connectée" });

  try {
    const result = await pool.query('SELECT * FROM public.agents WHERE name = $1 AND password = $2', [name, password]);
    if (result.rows.length > 0) {
      return res.json({ success: true, name: result.rows[0].name });
    }
    return res.status(401).json({ success: false, message: "Mot de passe incorrect" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /entries - Récupération des codifications
router.get('/entries', async (req, res) => {
  if (!pool) return res.status(500).json({ error: "Base de données non connectée. Vérifiez DATABASE_URL sur Vercel." });
  try {
    const result = await pool.query('SELECT * FROM public.entries ORDER BY ts DESC');
    const formatted = result.rows.map(e => ({
      id: e.id,
      ref: e.ref || "",
      motifId: e.motif_id,
      callerType: e.caller_type || null,
      comment: e.comment || null,
      agent: e.agent,
      date: e.date,
      time: e.time,
      ts: e.ts ? (e.ts instanceof Date ? e.ts.toISOString() : new Date(e.ts).toISOString()) : new Date().toISOString()
    }));
    return res.json(formatted);
  } catch (err) {
    console.error("Erreur GET /entries:", err);
    return res.status(500).json({ error: err.message });
  }
});

// POST /entries - Enregistrement d'un nouvel appel
router.post('/entries', async (req, res) => {
  const entry = req.body;
  if (!entry || !entry.motifId || !entry.agent) {
    return res.status(400).json({ error: "Champs requis manquants (motifId, agent)" });
  }
  if (!pool) return res.status(500).json({ error: "Base de données non connectée" });

  const id = entry.id || Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  const ref = entry.ref || "";
  const motifId = entry.motifId;
  const callerType = entry.callerType || null;
  const comment = entry.comment || null;
  const agent = entry.agent;
  const date = entry.date;
  const time = entry.time;
  const ts = entry.ts || new Date().toISOString();

  try {
    const query = `
      INSERT INTO public.entries (id, ref, motif_id, caller_type, comment, agent, date, time, ts)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        ref = EXCLUDED.ref,
        motif_id = EXCLUDED.motif_id,
        caller_type = EXCLUDED.caller_type,
        comment = EXCLUDED.comment,
        agent = EXCLUDED.agent,
        date = EXCLUDED.date,
        time = EXCLUDED.time,
        ts = EXCLUDED.ts
    `;
    await pool.query(query, [id, ref, motifId, callerType, comment, agent, date, time, ts]);
    return res.json({ success: true, entry: { id, ref, motifId, callerType, comment, agent, date, time, ts } });
  } catch (err) {
    console.error("Erreur POST /entries:", err);
    return res.status(500).json({ error: err.message });
  }
});

// GET /agents - Liste des conseillers
router.get('/agents', async (req, res) => {
  if (!pool) return res.status(500).json({ error: "Base de données non connectée. Vérifiez DATABASE_URL sur Vercel." });
  try {
    const result = await pool.query('SELECT name, password FROM public.agents ORDER BY name ASC');
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /agents - Gestion des comptes
router.post('/agents', async (req, res) => {
  const { agents } = req.body;
  if (!Array.isArray(agents)) return res.status(400).json({ error: "Tableau 'agents' requis" });
  if (!pool) return res.status(500).json({ error: "Base de données non connectée" });

  try {
    const names = agents.map(a => a.name);
    if (names.length > 0) {
      await pool.query('DELETE FROM public.agents WHERE NOT (name = ANY($1::text[]))', [names]);
      for (const a of agents) {
        await pool.query('INSERT INTO public.agents (name, password) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET password = EXCLUDED.password', [a.name, a.password]);
      }
    } else {
      await pool.query('DELETE FROM public.agents');
    }
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /notes - Récupérer les notes internes
router.get('/notes', async (req, res) => {
  if (!pool) return res.json({ refs: {}, agents: {} });
  try {
    const result = await pool.query('SELECT id, data FROM public.notes');
    const notes = { refs: {}, agents: {} };
    result.rows.forEach(row => {
      if (row.id === 'refs') notes.refs = row.data || {};
      if (row.id === 'agents') notes.agents = row.data || {};
    });
    return res.json(notes);
  } catch (err) {
    return res.json({ refs: {}, agents: {} });
  }
});

// POST /notes - Sauvegarder les notes internes
router.post('/notes', async (req, res) => {
  const notes = req.body;
  if (!pool) return res.status(500).json({ error: "Base de données non connectée" });

  try {
    const refsData = JSON.stringify(notes.refs || {});
    const agentsData = JSON.stringify(notes.agents || {});

    await pool.query('INSERT INTO public.notes (id, data) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data', ['refs', refsData]);
    await pool.query('INSERT INTO public.notes (id, data) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data', ['agents', agentsData]);

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /settings - Récupérer les paramètres
router.get('/settings', async (req, res) => {
  if (!pool) return res.json({ threshold: 3 });
  try {
    const result = await pool.query("SELECT value FROM public.settings WHERE key = 'threshold'");
    if (result.rows.length > 0) {
      return res.json({ threshold: parseInt(result.rows[0].value) || 3 });
    }
    return res.json({ threshold: 3 });
  } catch (err) {
    return res.json({ threshold: 3 });
  }
});

// POST /settings - Enregistrer le seuil d'alerte
router.post('/settings', async (req, res) => {
  const { threshold } = req.body;
  if (!pool) return res.status(500).json({ error: "Base de données non connectée" });

  try {
    await pool.query("INSERT INTO public.settings (key, value) VALUES ('threshold', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", [String(threshold)]);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Monter le routeur sur /api et /
app.use('/api', router);
app.use('/', router);

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Serveur Express (PostgreSQL Pool) démarré sur http://localhost:${PORT}`));
}
