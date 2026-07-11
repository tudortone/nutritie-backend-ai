const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const os = require('os');
const path = require('path');

require('dotenv').config();

// 1.2 Validare chei de mediu la startup (Crash-on-boot)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const geminiApiKey = process.env.GEMINI_API_KEY;
const groqApiKey = process.env.GROQ_API_KEY;
const corsOriginsEnv = process.env.CORS_ORIGINS || '*';

const missingVars = [];
if (!supabaseUrl) missingVars.push('SUPABASE_URL');
if (!supabaseAnonKey) missingVars.push('SUPABASE_ANON_KEY');
if (!geminiApiKey) missingVars.push('GEMINI_API_KEY');
if (!groqApiKey) missingVars.push('GROQ_API_KEY');

if (missingVars.length > 0) {
  console.error(`EROARE CRITICĂ: Lipsesc variabilele de mediu obligatorii: ${missingVars.join(', ')}`);
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(compression());
const port = process.env.PORT || 3000;

// 1.3 CORS Securizat și restrictiv
const corsOrigins = corsOriginsEnv.split(',').map(o => o.trim());

app.use(cors({
  origin: corsOrigins.includes('*') ? true : corsOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate Limiting general pentru API
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute
  max: 100, // max 100 cereri per fereastră per IP
  message: { eroare: "Prea multe cereri. Încearcă mai târziu." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', generalLimiter);

// 1.4 Rate Limiting strict pentru endpoint-urile AI (15 cereri pe minut)
const aiRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minut
  max: 15, // max 15 cereri per minut per IP
  message: { eroare: "Ai depășit limita de 15 cereri pe minut pentru AI. Te rugăm să aștepți un minut." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Upload pe disc temporar pentru prevenirea OOM (Out of Memory)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, os.tmpdir());
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'nutri-' + uniqueSuffix + path.extname(file.originalname || '.jpg'));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const validTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (validTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tip fișier nepermis. Doar imagini JPEG/PNG/WEBP sunt acceptate.'));
    }
  }
});

// Inițializare Supabase pentru validarea token-ului JWT și operațiuni DB sigure
const supabase = createClient(supabaseUrl, supabaseAnonKey);
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || supabaseAnonKey;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

// Cache in-memory TTL (60 secunde) pentru token-uri JWT
const tokenCache = new Map();
const CACHE_TTL_MS = 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokenCache.entries()) {
    if (now > data.expiresAt) tokenCache.delete(token);
  }
}, 5 * 60 * 1000).unref();

// Helper pentru validarea magic bytes ale imaginilor
const validateImageMagicBytes = (buffer) => {
  if (!buffer || buffer.length < 12) return false;
  // JPEG (FF D8 FF)
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;
  // PNG (89 50 4E 47)
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;
  // WEBP (RIFF....WEBP)
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return true;
  // HEIC / HEIF / ISO Media (ftyp box)
  const ftyp = buffer.toString('ascii', 4, 8);
  if (ftyp === 'ftyp') return true;
  return false;
};

// Middleware Autentificare cu Cache TTL
const requireAuth = async (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  const authHeader = req.headers.authorization;
  if (process.env.NODE_ENV === 'development') {
    console.log("=== Incoming Request ===");
    console.log("Method:", req.method);
  }
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ eroare: "Acces neautorizat. Token lipsă." });
  }
  const token = authHeader.split(' ')[1];
  const now = Date.now();
  const cached = tokenCache.get(token);
  if (cached && now < cached.expiresAt) {
    req.user = cached.user;
    return next();
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
      tokenCache.delete(token);
      return res.status(401).json({ eroare: "Token invalid sau expirat." });
    }
    tokenCache.set(token, { user, expiresAt: now + CACHE_TTL_MS });
    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({ eroare: "Eroare la validarea autentificării." });
  }
};

// Inițializare AI Gemini și listă modele în cascadă (modele stabile prioritar)
const genAI = new GoogleGenerativeAI(geminiApiKey);
const getGeminiModelsList = () => {
  return [
    process.env.GEMINI_MODEL,
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash"
  ].filter((v, i, a) => v && a.indexOf(v) === i);
};

// Helper pentru timeout cereri Gemini (30 secunde)
const callWithTimeout = (promise, ms = 30000) => {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Cererea către Gemini a expirat (Timeout 30s).')), ms)
  );
  return Promise.race([promise, timeout]);
};

// Helper pentru extragere chei API multiple din variabile de mediu (rotație automată la eroare/cotă depășită)
const getApiKeysList = (envPrefix) => {
  const keys = [];
  if (process.env[envPrefix]) keys.push(process.env[envPrefix]);
  if (process.env[`${envPrefix}S`]) {
    process.env[`${envPrefix}S`].split(',').forEach(k => {
      const trimmed = k.trim();
      if (trimmed) keys.push(trimmed);
    });
  }
  for (let i = 2; i <= 5; i++) {
    if (process.env[`${envPrefix}_${i}`]) keys.push(process.env[`${envPrefix}_${i}`]);
  }
  return keys.filter((v, i, a) => v && a.indexOf(v) === i);
};

// ==========================================
// REGISTRU STARE FURNIZORI AI (COOLDOWN & STATUS)
// ==========================================
const aiStatusRegistry = {
  gemini: { nume: "Google Gemini 2.5", status: "active", blockedUntil: 0, ultimulMesaj: "Disponibil" },
  openai: { nume: "OpenAI GPT-4o-mini", status: "active", blockedUntil: 0, ultimulMesaj: "Disponibil" },
  groq: { nume: "Groq Vision", status: "active", blockedUntil: 0, ultimulMesaj: "Disponibil" },
  openrouter: { nume: "OpenRouter Vision", status: "active", blockedUntil: 0, ultimulMesaj: "Disponibil" }
};

const blockProvider = (providerKey, cooldownSeconds, motiv) => {
  if (aiStatusRegistry[providerKey]) {
    aiStatusRegistry[providerKey].status = "cooldown";
    aiStatusRegistry[providerKey].blockedUntil = Date.now() + cooldownSeconds * 1000;
    aiStatusRegistry[providerKey].ultimulMesaj = motiv;
  }
};

const getProviderStatus = (providerKey) => {
  const p = aiStatusRegistry[providerKey];
  if (!p) return { id: providerKey, nume: providerKey, status: "active", secundeRamase: 0, mesaj: "Disponibil" };
  const acum = Date.now();
  if (p.blockedUntil > acum) {
    const sec = Math.ceil((p.blockedUntil - acum) / 1000);
    return { id: providerKey, nume: p.nume, status: "cooldown", secundeRamase: sec, mesaj: `Blocat (${sec}s): ${p.ultimulMesaj}` };
  } else {
    p.status = "active";
    p.blockedUntil = 0;
    p.ultimulMesaj = "Disponibil";
    return { id: providerKey, nume: p.nume, status: "active", secundeRamase: 0, mesaj: "Disponibil" };
  }
};

app.get('/api/ai-status', (req, res) => {
  res.json({
    gemini: getProviderStatus('gemini'),
    openai: getProviderStatus('openai'),
    groq: getProviderStatus('groq'),
    openrouter: getProviderStatus('openrouter')
  });
});

// ==========================================
// RUTE DE HEALTH CHECK & ROOT
// ==========================================
app.get('/', (req, res) => {
  res.json({
    status: "OK",
    service: "NutriAI Secure Backend",
    version: "2.2.0-ai-selector",
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', healthy: true, uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ==========================================
// RUTE API PROTEJATE CU JWT
// ==========================================

// RUTA 1: ANALIZA FOTO STRUCTURATĂ (GEMINI)
const handleAnalizaFoto = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ eroare: "Te rog încarcă o imagine." });
    }

    // 1.1 Validare strictă mimetype (trebuie să fie imagine) înainte de a apela Gemini
    if (!req.file.mimetype || !req.file.mimetype.startsWith('image/')) {
      return res.status(400).json({ eroare: "Tip fișier nepermis. Doar fișierele de tip imagine sunt acceptate." });
    }

    const fileBuffer = await fs.promises.readFile(req.file.path);
    if (!validateImageMagicBytes(fileBuffer)) {
      return res.status(400).json({ eroare: "Tip fișier nepermis. Doar imagini JPEG/PNG/WEBP sunt acceptate." });
    }

    const imagePart = {
      inlineData: {
        data: fileBuffer.toString("base64"),
        mimeType: req.file.mimetype
      },
    };

    const prompt = `Analizează această imagine cu mâncare.
Consideră o farfurie standard de ~25cm diametru ca referință de scară (E1). Folosește baze de date nutriționale recunoscute (cum ar fi USDA) pentru o precizie cât mai mare.
Identifică TOATE alimentele de pe farfurie separat. Pentru fiecare aliment, estimează cantitatea vizuală în grame, oferă valorile nutriționale PENTRU SUTA DE GRAME (100g) și adaugă nivelul tău de încredere în estimare (E4).
RETURNEAZĂ DOAR UN ARRAY JSON în următorul format (fără text înainte sau după):
[
  {
    "nume": "numele alimentului 1",
    "estimare_grame": număr grame estimat de tine vizual,
    "calorii_per_100g": număr calorii per 100g,
    "proteine_per_100g": grame proteină per 100g,
    "grasimi_per_100g": grame grăsime per 100g,
    "carbohidrati_per_100g": grame carbohidrați per 100g,
    "incredere": "ridicat"
  }
]`;

    let text = null;
    let lastError = null;
    const imageBase64 = fileBuffer.toString("base64");
    const imageMime = req.file.mimetype;
    const requestedProvider = (req.body?.provider || req.query?.provider || 'auto').toLowerCase();

    if (requestedProvider !== 'auto' && aiStatusRegistry[requestedProvider]) {
      const st = getProviderStatus(requestedProvider);
      if (st.status === 'cooldown') {
        return res.status(429).json({
          eroare: `Modelul selectat (${st.nume}) este blocat temporar pentru încă ${st.secundeRamase}s (${st.mesaj}). Alege alt model sau modul Auto.`,
          providerStatus: 'cooldown',
          secundeRamase: st.secundeRamase
        });
      }
    }

    // 1) PRIORITATE: OpenAI GPT-4o-mini Vision (sau dacă s-a cerut specific openai)
    const runOpenAI = (requestedProvider === 'auto' || requestedProvider === 'openai');
    const openaiKeys = getApiKeysList('OPENAI_API_KEY');
    if (runOpenAI && openaiKeys.length > 0) {
      console.log("🔄 Încerc OpenAI GPT-4o-mini Vision...");
      for (const key of openaiKeys) {
        try {
          const oaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${key}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              model: "gpt-4o-mini",
              messages: [
                {
                  role: "user",
                  content: [
                    { type: "text", text: prompt },
                    {
                      type: "image_url",
                      image_url: { url: `data:${imageMime};base64,${imageBase64}` }
                    }
                  ]
                }
              ],
              temperature: 0.2,
              max_tokens: 1500
            })
          });
          if (oaiRes.ok) {
            const oaiData = await oaiRes.json();
            text = oaiData.choices?.[0]?.message?.content;
            if (text) {
              console.log("✅ Succes OpenAI GPT-4o-mini Vision!");
              break;
            }
          } else {
            if (oaiRes.status === 429) blockProvider('openai', 60, "Limită de cereri (429)");
            const errBody = await oaiRes.text();
            console.warn(`⚠️ OpenAI Vision eșuat (${oaiRes.status}):`, errBody.substring(0, 150));
          }
        } catch (e) {
          console.warn("⚠️ OpenAI Vision excepție:", e.message);
        }
      }
    }

    // 2) Groq Vision AI (sau dacă s-a cerut specific groq)
    const runGroq = (!text && (requestedProvider === 'auto' || requestedProvider === 'groq'));
    if (runGroq) {
      console.log("🔄 Încerc Groq Vision AI...");
      const groqKeys = getApiKeysList('GROQ_API_KEY');
      const groqVisionModels = ["meta-llama/llama-4-scout-17b-16e-instruct", "meta-llama/llama-4-maverick-17b-128e-instruct"];
      for (const key of groqKeys) {
        for (const groqModel of groqVisionModels) {
          try {
            const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${key}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                model: groqModel,
                messages: [
                  {
                    role: "user",
                    content: [
                      { type: "text", text: prompt },
                      {
                        type: "image_url",
                        image_url: { url: `data:${imageMime};base64,${imageBase64}` }
                      }
                    ]
                  }
                ],
                temperature: 0.2,
                max_tokens: 1000
              })
            });

            if (groqRes.ok) {
              const groqData = await groqRes.json();
              text = groqData.choices?.[0]?.message?.content;
              if (text) {
                console.log(`✅ Succes Groq Vision cu modelul: ${groqModel}`);
                break;
              }
            } else {
              if (groqRes.status === 429) blockProvider('groq', 60, "Limită de cereri Groq (429)");
              const errBody = await groqRes.text();
              console.warn(`⚠️ Groq [${groqModel}] (${groqRes.status}):`, errBody.substring(0, 100));
            }
          } catch (groqErr) {
            console.warn(`⚠️ Groq Vision [${groqModel}] excepție:`, groqErr.message);
          }
        }
        if (text) break;
      }
    }

    // 3) Gemini AI fallback (sau dacă s-a cerut specific gemini)
    const runGemini = (!text && (requestedProvider === 'auto' || requestedProvider === 'gemini'));
    if (runGemini) {
      console.warn("🔄 Încerc Gemini API...");
      const geminiKeys = getApiKeysList('GEMINI_API_KEY');
      const modelsToTry = getGeminiModelsList();
      for (const key of geminiKeys) {
        const client = new GoogleGenerativeAI(key);
        for (const modelName of modelsToTry) {
          try {
            const model = client.getGenerativeModel({ model: modelName });
            const responsePromise = model.generateContent({
              contents: [{ role: "user", parts: [{ text: prompt }, imagePart] }],
              generationConfig: { responseMimeType: "application/json" }
            });
            const result = await callWithTimeout(responsePromise);
            if (result && result.response) {
              text = result.response.text();
              if (text) {
                console.log(`✅ Succes Gemini cu modelul: ${modelName}`);
                break;
              }
            }
          } catch (err) {
            lastError = err;
            const errMsg = err.message || String(err);
            if (errMsg.includes('429')) blockProvider('gemini', 60, "Limită de cereri Gemini (429)");
            console.warn(`⚠️ Gemini [${modelName}] eșuat:`, errMsg.substring(0, 100));
          }
        }
        if (text) break;
      }
    }

    // 4) OpenRouter Vision fallback (dacă există OPENROUTER_API_KEY)
    if (!text) {
      const orKeys = getApiKeysList('OPENROUTER_API_KEY');
      if (orKeys.length > 0) {
        console.warn("⚠️ Încerc OpenRouter AI...");
        for (const key of orKeys) {
          try {
            const orRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${key}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                model: "google/gemini-flash-1.5",
                messages: [
                  {
                    role: "user",
                    content: [
                      { type: "text", text: prompt },
                      {
                        type: "image_url",
                        image_url: { url: `data:${imageMime};base64,${imageBase64}` }
                      }
                    ]
                  }
                ]
              })
            });
            if (orRes.ok) {
              const orData = await orRes.json();
              text = orData.choices?.[0]?.message?.content;
              if (text) {
                console.log("✅ Succes OpenRouter Vision!");
                break;
              }
            }
          } catch (e) {}
        }
      }
    }

    if (!text) {
      console.error("AI vision fail.");
      return res.status(503).json({
        eroare: "Toate sistemele AI au eșuat sau sunt temporar în limită de cereri (cooldown). Încearcă din nou peste un minut sau schimbă modelul AI.",
        stareAI: {
          gemini: getProviderStatus('gemini'),
          openai: getProviderStatus('openai'),
          groq: getProviderStatus('groq')
        }
      });
    }

    let cleanedText = text.replace(/```json/g, '').replace(/```/g, '').trim();
    let parsed;
    try {
      parsed = JSON.parse(cleanedText);
    } catch (e) {
      const jsonMatch = cleanedText.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        try {
          parsed = JSON.parse(jsonMatch[0]);
        } catch (e2) {
          console.warn("⚠️ Eroare parsing array JSON din text:", e2.message);
        }
      }
      if (!parsed) {
        const objMatch = cleanedText.match(/\{[\s\S]*\}/);
        if (objMatch) {
          try {
            parsed = JSON.parse(objMatch[0]);
          } catch (e3) {
            console.warn("⚠️ Eroare parsing obiect JSON din text:", e3.message);
          }
        }
      }
      if (!parsed) {
        return res.status(500).json({ eroare: "AI nu a returnat un format JSON valid." });
      }
    }

    if (!Array.isArray(parsed)) {
      const arrayProp = Object.values(parsed).find(val => Array.isArray(val));
      if (arrayProp) {
        parsed = arrayProp;
      } else {
        parsed = [parsed];
      }
    }

    // Schema de validare / normalizare
    const validated = parsed.map(item => ({
      nume: String(item.nume || item.aliment || "Aliment identificat"),
      estimare_grame: Number(item.estimare_grame || item.grame) || 100,
      calorii_per_100g: Number(item.calorii_per_100g || item.calorii) || 0,
      proteine_per_100g: Number(item.proteine_per_100g || item.proteine) || 0,
      grasimi_per_100g: Number(item.grasimi_per_100g || item.grasimi) || 0,
      carbohidrati_per_100g: Number(item.carbohidrati_per_100g || item.carbohidrati) || 0,
      incredere: String(item.incredere || "ridicat")
    }));

    res.json(validated);
  } catch (error) {
    console.error("Eroare Gemini structurat:", error.message || error);
    const msg = error?.message || "Eroare necunoscută de la AI";
    res.status(500).json({ eroare: `Eroare AI Gemini: ${msg}` });
  } finally {
    // 1.2 Ștergerea asincronă a fișierului temporar în blocul finally
    if (req.file && req.file.path) {
      fs.promises.unlink(req.file.path).catch(() => {});
    }
  }
};

app.post("/api/analiza-foto", requireAuth, aiRateLimiter, upload.single("imagine"), handleAnalizaFoto);
app.post("/api/analizeaza-mancare-structurat", requireAuth, aiRateLimiter, upload.single("imagine"), handleAnalizaFoto);

// ==========================================
// RUTA 2: CHAT CONVERSAȚIONAL (GROQ / LLAMA 3.3)
// Securizată cu requireAuth
// ==========================================
app.post('/api/chat', requireAuth, aiRateLimiter, async (req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ raspuns: "Format cerere invalid. Se așteaptă un obiect JSON." });
    }
    let { mesaj, mesaje, caloriiConsumate, caloriiTinta, proteineConsumate, proteineTinta } = req.body;
    const calCons = Number(caloriiConsumate) || 0;
    const calTinta = Number(caloriiTinta) || 2000;
    const protCons = Number(proteineConsumate) || 0;
    const protTinta = Number(proteineTinta) || 150;

    let ultimulMesaj = mesaj;
    if (Array.isArray(mesaje) && mesaje.length > 0) {
      ultimulMesaj = mesaje[mesaje.length - 1].text || mesaje[mesaje.length - 1].content || '';
    }

    if (!ultimulMesaj || typeof ultimulMesaj !== 'string' || !ultimulMesaj.trim()) {
      return res.status(400).json({ raspuns: "Serverul nu a primit niciun mesaj valid." });
    }

    ultimulMesaj = ultimulMesaj.replace(/[\x00-\x1F\x7F]/g, "").trim();
    if (ultimulMesaj.length > 500) {
      ultimulMesaj = ultimulMesaj.substring(0, 500);
    }

    const systemPrompt = `Ești un asistent nutrițional prietenos, profesionist și empatic pentru aplicația NutriAI.
REGULA TA PRINCIPALĂ: Răspunde STRICT și EXCLUSIV la întrebări despre nutriție, diete, calorii, antrenamente și fitness.
Dacă utilizatorul te întreabă absolut orice altceva (programare, politică, cultură generală, mașini, glume, istorie etc.), trebuie să REFUZI POLITICOS și să îi amintești că ești setat doar pentru discuții despre sănătate și nutriție.

Contextul utilizatorului de astăzi:
- Calorii: a mâncat ${calCons} dintr-o țintă de ${calTinta} kcal.
- Proteine: a mâncat ${protCons}g dintr-o țintă de ${protTinta}g.

Instrucțiuni de formatare și stil:
1. Folosește emoji-uri relevante la începutul propozițiilor sau ideilor importante (de exemplu 🥗, 🔥, 🥩, 💡, ✅).
2. Structurează răspunsul cu bullet points dacă oferi mai mult de 2 sugestii sau opțiuni de mese.
3. Răspunde concis, clar și la obiect. Poți folosi maximum 6-8 propoziții dacă utilizatorul cere explicații detaliate sau planuri de mese.

Sarcina ta: Răspunde prietenos, ținând cont de istoricul discuției și de caloriile/proteinele rămase astăzi.`;

    const messages = [
      { role: "system", content: systemPrompt }
    ];

    if (Array.isArray(mesaje) && mesaje.length > 0) {
      const istoric = mesaje.slice(-10);
      istoric.forEach((m, idx) => {
        let role = m.role === 'user' || m.sender === 'user' ? 'user' : 'assistant';
        let content = m.text || m.content || '';
        if (idx === istoric.length - 1) content = ultimulMesaj;
        if (content.trim()) {
          messages.push({ role, content });
        }
      });
    } else {
      messages.push({ role: "user", content: ultimulMesaj });
    }

    // 1.3 Limitare istoric conversație Groq bazată pe estimare de tokens (caractere / 3.5)
    // Păstrăm maximum 6000 de tokens, asigurându-ne că primul mesaj (System Prompt) rămâne mereu la indexul 0.
    const getEstimatedTokens = (arr) => arr.reduce((acc, m) => acc + Math.ceil((m.content ? m.content.length : 0) / 3.5), 0);
    let totalTokens = getEstimatedTokens(messages);
    while (totalTokens > 6000 && messages.length > 2) {
      messages.splice(1, 1);
      totalTokens = getEstimatedTokens(messages);
    }

    try {
      const fetchPromise = fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${groqApiKey}`
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          messages: messages,
          temperature: 0.7,
          max_tokens: 800
        })
      });

      const response = await callWithTimeout(fetchPromise, 35000);
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Eroare Groq API (${response.status}): ${errorText}`);
      }

      const data = await response.json();
      const raspunsText = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : "Nu am putut genera un răspuns.";
      return res.json({ raspuns: raspunsText });
    } catch (groqError) {
      console.warn("Eroare Groq API în /api/chat, activăm fallback Gemini text:", groqError.message || groqError);
      
      const geminiPrompt = `${systemPrompt}\n\nIstoricul conversației și întrebarea curentă:\n${messages.map(m => `${m.role.toUpperCase()}: ${m.content}`).join('\n\n')}\n\nASSISTANT:`;
      const modelList = getGeminiModelsList().filter(Boolean);
      for (const modelName of modelList) {
        try {
          const model = genAI.getGenerativeModel({ model: modelName });
          const result = await callWithTimeout(model.generateContent(geminiPrompt), 30000);
          const raspunsText = result.response.text();
          if (raspunsText) {
            return res.json({ raspuns: raspunsText });
          }
        } catch (gemErr) {
          console.warn(`Fallback Gemini (${modelName}) a eșuat în /api/chat:`, gemErr.message);
        }
      }
      throw groqError;
    }
  } catch (error) {
    console.error("Eroare la generarea chat-ului AI:", error);
    res.status(500).json({ raspuns: "A apărut o problemă de conexiune cu asistentul AI. Te rugăm să mai încerci peste câteva momente!" });
  }
});

// ==========================================
// ==========================================
// RUTA: ESTIMARE RAPIDĂ TEXT ALIMENT (GROQ/LLM)
// ==========================================
app.post('/api/estimeaza-mancare-text', requireAuth, aiRateLimiter, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || typeof text !== 'string') return res.status(400).json({ eroare: "Text invalid." });
    let curatat = text.replace(/[\x00-\x1F\x7F]/g, "").trim();
    if (curatat.length > 200) curatat = curatat.substring(0, 200);
    if (!curatat) return res.status(400).json({ eroare: "Text invalid." });
    
    const prompt = `Estimează valorile nutriționale pentru 1 porție standard din: "${curatat}". RETURNEAZĂ STRICT UN OBIECT JSON în formatul: {"nume": "${curatat}", "calorii": 300, "proteine": 15, "carbohidrati": 30, "grasimi": 10, "gramajDefault": 150}. Fără text adițional.`;
    
    const fetchPromise = fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": `Bearer ${groqApiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        response_format: { type: "json_object" }
      })
    });
    const groqResponse = await callWithTimeout(fetchPromise, 25000);
    if (!groqResponse.ok) {
      throw new Error(`Eroare Groq API (${groqResponse.status})`);
    }
    const data = await groqResponse.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("Răspuns gol primit de la AI.");
    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (e) {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error("Nu s-a putut interpreta răspunsul ca JSON.");
      }
    }
    res.json(parsed);
  } catch (error) {
    console.error("Eroare estimare AI aliment:", error.message);
    res.status(500).json({ eroare: "Nu s-a putut estima alimentul cu AI." });
  }
});

// ==========================================
// RUTA 2.1: PROXY PENTRU OPENFOODFACTS BARCODE + STRAT 1 CACHE LOCAL + STRAT 3 FALLBACK
// ==========================================
app.get('/api/produs-barcode/:code', requireAuth, async (req, res) => {
  try {
    const code = (req.params.code || '').trim();
    if (!code || code.length < 4) {
      return res.status(400).json({ eroare: "Cod de bare invalid." });
    }

    // STRAT 1: Verificare Cache Local Supabase
    try {
      const { data: cachedItem } = await supabaseAdmin
        .from('barcode_cache')
        .select('*')
        .eq('code', code)
        .maybeSingle();

      if (cachedItem) {
        return res.json({
          source: 'cache',
          produs: {
            codBare: code,
            nume: cachedItem.name,
            brand: cachedItem.brand || '',
            cantitate: cachedItem.quantity || '',
            calorii: Number(cachedItem.kcal_100g || 0),
            proteine: Number(cachedItem.protein_100g || 0),
            carbohidrati: Number(cachedItem.carbs_100g || 0),
            grasimi: Number(cachedItem.fat_100g || 0),
          }
        });
      }
    } catch (cacheErr) {
      console.warn("Avertisment citire barcode_cache:", cacheErr.message);
    }

    // STRAT 2: Căutare în OpenFoodFacts API
    const fetchPromise = fetch(`https://world.openfoodfacts.org/api/v2/product/${code}.json`, {
      headers: { 'User-Agent': 'NutriAI - React Native App - Contact: tudortone' }
    });
    const resp = await callWithTimeout(fetchPromise, 12000);
    if (resp.ok) {
      const data = await resp.json();
      const product = data?.product;
      if (data?.status === 1 && product) {
        const nutriments = product.nutriments || {};
        const normalized = {
          codBare: code,
          nume: product.product_name || product.product_name_ro || 'Produs necunoscut',
          brand: product.brands || '',
          cantitate: product.quantity || '',
          calorii: Number(nutriments['energy-kcal_100g'] || nutriments['energy-kcal'] || 0),
          proteine: Number(nutriments.proteins_100g || 0),
          carbohidrati: Number(nutriments.carbohydrates_100g || 0),
          grasimi: Number(nutriments.fat_100g || 0),
        };

        try {
          await supabaseAdmin.from('barcode_cache').upsert({
            code,
            source: 'openfoodfacts',
            brand: normalized.brand,
            name: normalized.nume,
            quantity: normalized.cantitate,
            kcal_100g: normalized.calorii,
            protein_100g: normalized.proteine,
            carbs_100g: normalized.carbohidrati,
            fat_100g: normalized.grasimi,
            payload: product,
            updated_at: new Date().toISOString(),
          });
        } catch (saveErr) {
          console.warn("Nu s-a putut salva în barcode_cache:", saveErr.message);
        }

        return res.json({ source: 'openfoodfacts', produs: normalized });
      }
    }

    // STRAT 3: Fallback controlat - Produs negăsit
    return res.status(404).json({
      eroare: "Produsul nu a fost găsit.",
      allowManualEntry: true,
      suggestedAction: "manual_or_ai_text",
    });
  } catch (err) {
    console.error("Eroare interogare barcode OpenFoodFacts proxy:", err.message);
    return res.status(500).json({ eroare: "Eroare la interogarea codului de bare." });
  }
});

// ==========================================
// RUTA 2.2: SALVARE PRODUS BARCODE COMPLETAT MANUAL ÎN CACHE LOCAL
// ==========================================
app.post('/api/salveaza-produs-barcode', requireAuth, async (req, res) => {
  try {
    const { code, name, brand, quantity, kcal_100g, protein_100g, carbs_100g, fat_100g } = req.body;
    if (!code || !name) {
      return res.status(400).json({ eroare: "Codul și numele produsului sunt obligatorii." });
    }
    await supabaseAdmin.from('barcode_cache').upsert({
      code: String(code).trim(),
      source: 'user_manual',
      brand: brand || '',
      name: String(name).trim(),
      quantity: quantity || '',
      kcal_100g: Number(kcal_100g || 0),
      protein_100g: Number(protein_100g || 0),
      carbs_100g: Number(carbs_100g || 0),
      fat_100g: Number(fat_100g || 0),
      payload: req.body,
      updated_at: new Date().toISOString(),
    });
    return res.json({ succes: true, message: "Produs salvat în cache-ul local." });
  } catch (err) {
    console.error("Eroare la salvare produs barcode:", err.message);
    return res.status(500).json({ eroare: "Eroare la salvarea produsului." });
  }
});

// ==========================================
// RUTA 3: CALCUL PROFIL NUTRIȚIONAL (DETERMINIST)
// Securizată cu requireAuth
// ==========================================
app.post('/api/calculeaza-profil', requireAuth, async (req, res) => {
  try {
    const { varsta, greutate, inaltime, sex, activitate, obiectiv } = req.body;

    if (!varsta || !greutate || !inaltime || !sex || !activitate || !obiectiv) {
      return res.status(400).json({ eroare: "Date incomplete. Te rog să completezi tot formularul." });
    }

    const v = parseInt(varsta);
    const g = parseFloat(greutate);
    const i = parseFloat(inaltime);

    if (isNaN(v) || v < 10 || v > 100) {
      return res.status(400).json({ eroare: "Vârsta trebuie să fie un număr valid între 10 și 100 ani." });
    }
    if (isNaN(g) || g < 30 || g > 300) {
      return res.status(400).json({ eroare: "Greutatea trebuie să fie un număr valid între 30 și 300 kg." });
    }
    if (isNaN(i) || i < 100 || i > 250) {
      return res.status(400).json({ eroare: "Înălțimea trebuie să fie un număr valid între 100 și 250 cm." });
    }
    if (sex !== 'Masculin' && sex !== 'Feminin') {
      return res.status(400).json({ eroare: "Sexul selectat este invalid." });
    }
    const activitatiPermise = ['Sedentar', 'Moderat', 'Foarte Activ'];
    if (!activitatiPermise.includes(activitate)) {
      return res.status(400).json({ eroare: "Nivelul de activitate selectat este invalid." });
    }
    const obiectivePermise = ['Slăbire', 'Menținere', 'Masă Musculară'];
    if (!obiectivePermise.includes(obiectiv)) {
      return res.status(400).json({ eroare: "Obiectivul selectat este invalid." });
    }

    // Calcul direct, instant și determinist Mifflin-St Jeor (B1, B2)
    let bmr;
    if (sex === 'Masculin') {
      bmr = 10 * g + 6.25 * i - 5 * v + 5;
    } else {
      bmr = 10 * g + 6.25 * i - 5 * v - 161;
    }
    
    // Corectare multiplicatori conform literaturii (B2)
    const multiplicatori = { 'Sedentar': 1.2, 'Moderat': 1.55, 'Foarte Activ': 1.725 };
    const tdee = bmr * (multiplicatori[activitate] || 1.2);
    
    let caloriiTinta;
    if (obiectiv === 'Slăbire') {
      caloriiTinta = Math.max(tdee - 500, sex === 'Masculin' ? 1500 : 1200);
    } else if (obiectiv === 'Masă Musculară') {
      caloriiTinta = tdee + 350;
    } else {
      caloriiTinta = tdee;
    }
    
    const protPerKg = obiectiv === 'Menținere' ? 1.6 : 2.0;
    const proteineTinta = Math.round(g * protPerKg);
    
    const calT = Math.round(caloriiTinta);
    const grasimiTinta = Math.round((calT * 0.25) / 9); // 25% din calorii, 9 kcal/g
    const carbiTinta = Math.round(Math.max((calT - (proteineTinta * 4) - (grasimiTinta * 9)) / 4, 50));
    
    res.json({ caloriiTinta: calT, proteineTinta, grasimiTinta, carbiTinta });
    
  } catch (error) {
    console.error("Eroare la calculul profilului:", error.message);
    res.status(500).json({ eroare: "Îmi pare rău, am întâmpinat o problemă la calcul. Mai încearcă!" });
  }
});

// ==========================================
// RUTA 4: ȘTERGERE MASĂ
// ==========================================
app.delete('/api/mese/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabaseAdmin.from('mese').delete().eq('id', id).eq('user_id', req.user.id);
    if (error) return res.status(500).json({ eroare: error.message });
    res.json({ succes: true });
  } catch (error) {
    res.status(500).json({ eroare: "Eroare la ștergerea mesei." });
  }
});

// ==========================================
// RUTA 5: EDITARE MASĂ
// ==========================================
app.put('/api/mese/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { nume, calorii, proteine, grasimi, carbohidrati } = req.body;
    const { data, error } = await supabaseAdmin
      .from('mese')
      .update({ nume, calorii: Number(calorii), proteine: Number(proteine), grasimi: Number(grasimi), carbohidrati: Number(carbohidrati) })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select();
    if (error) return res.status(500).json({ eroare: error.message });
    res.json({ succes: true, masa: data[0] });
  } catch (error) {
    res.status(500).json({ eroare: "Eroare la actualizarea mesei." });
  }
});

// ==========================================
// HANDLER 404 PENTRU RUTE INEXISTENTE
// ==========================================
app.use((req, res, next) => {
  res.status(404).json({ eroare: "Ruta solicitată nu există (404)." });
});

// ==========================================
// HANDLER GLOBAL DE ERORI
// ==========================================
app.use((err, req, res, next) => {
  const message = err?.message || '';
  console.error("Eroare globală:", message);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ eroare: message });
  }
  if (message.includes('Tip fișier nepermis')) {
    return res.status(400).json({ eroare: message });
  }
  if (err?.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ eroare: "Fișierul este prea mare. Limita este 5MB." });
  }
  res.status(500).json({ eroare: "Eroare internă a serverului." });
});

// Export pentru teste
module.exports = app;

// ==========================================
// KEEP-ALIVE TICKER (MENTINERE SERVER ONLINE)
// Previne adormirea instanței pe platforme ca Render, Railway sau Heroku
// ==========================================
const startKeepAliveTicker = (serverPort) => {
  const intervalMinutes = parseFloat(process.env.KEEP_ALIVE_INTERVAL_MINUTES) || 10;
  const intervalMs = intervalMinutes * 60 * 1000;
  const targetUrl = process.env.KEEP_ALIVE_URL || process.env.RENDER_EXTERNAL_URL || `http://127.0.0.1:${serverPort}/health`;

  console.log(`⏱️ Keep-Alive Ticker activat: Ping automat către ${targetUrl} la fiecare ${intervalMinutes} minute.`);

  const ticker = setInterval(async () => {
    try {
      const res = await fetch(targetUrl);
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        console.log(`[${new Date().toLocaleTimeString('ro-RO')}] 💓 Keep-Alive Ticker: Server activ (${res.status} OK). Timestamp: ${data.timestamp || 'N/A'}`);
      } else {
        console.warn(`[${new Date().toLocaleTimeString('ro-RO')}] ⚠️ Keep-Alive Ticker: Răspuns neașteptat (${res.status})`);
      }
    } catch (err) {
      console.error(`[${new Date().toLocaleTimeString('ro-RO')}] ❌ Keep-Alive Ticker Eroare:`, err.message);
    }
  }, intervalMs);

  if (ticker.unref) {
    ticker.unref();
  }
  
  return ticker;
};

// Pornire server doar dacă fișierul este rulat direct (nu importat în teste)
if (require.main === module) {
  app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Serverul securizat rulează pe http://0.0.0.0:${port}`);
    startKeepAliveTicker(port);
  });
}