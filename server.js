const express = require('express');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { createClient } = require('@supabase/supabase-js');

require('dotenv').config();

// 1.2 Validare chei de mediu la startup (Crash-on-boot)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const geminiApiKey = process.env.GEMINI_API_KEY;

if (!supabaseUrl || !supabaseAnonKey || !geminiApiKey) {
  console.error("ERRORE CRITICĂ: Lipsesc variabilele de mediu obligatorii (SUPABASE_URL, SUPABASE_ANON_KEY sau GEMINI_API_KEY).");
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3000;

// 1.3 CORS Securizat și restrictiv
const corsOriginsEnv = process.env.CORS_ORIGINS || '*';
const corsOrigins = corsOriginsEnv.split(',').map(o => o.trim());

app.use(cors({
  origin: corsOrigins.includes('*') ? true : corsOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1.4 Rate Limiting pe endpoint-urile AI
const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute
  max: 30, // max 30 cereri per fereastră per IP
  message: { eroare: "Prea multe cereri. Încearcă mai târziu." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', aiLimiter);

// Upload limitat și filtrare MIME Type
const upload = multer({ 
  storage: multer.memoryStorage(),
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

// Inițializare Supabase pentru validarea token-ului JWT
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Middleware Autentificare
const requireAuth = async (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  const authHeader = req.headers.authorization;
  console.log("=== Incoming Request ===");
  console.log("Method:", req.method);
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ eroare: "Acces neautorizat. Token lipsă." });
  }
  const token = authHeader.split(' ')[1];
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
      return res.status(401).json({ eroare: "Token invalid sau expirat." });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({ eroare: "Eroare la validarea autentificării." });
  }
};

// Inițializare AI Gemini - model stabil gemini-2.0-flash
const genAI = new GoogleGenerativeAI(geminiApiKey);
const modelGemini = genAI.getGenerativeModel({ model: process.env.GEMINI_MODEL || "gemini-2.0-flash" });

// Helper pentru timeout cereri Gemini (30 secunde)
const callWithTimeout = (promise, ms = 30000) => {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Cererea către Gemini a expirat (Timeout 30s).')), ms)
  );
  return Promise.race([promise, timeout]);
};

// ==========================================
// RUTE DE HEALTH CHECK & ROOT
// ==========================================
app.get('/', (req, res) => {
  res.json({
    nume: "NutriAI Backend Server",
    status: "online",
    versiune: "1.0.0",
    mesaj: "Serverul AI și Supabase funcționează corect!"
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==========================================
// RUTA 1: ANALIZA FOTO STRUCTURATĂ (GEMINI)
// Securizată cu requireAuth
// ==========================================
app.post('/api/analizeaza-mancare-structurat', requireAuth, upload.single('imagine'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ eroare: "Nu s-a primit nicio imagine." });
    }

    const imagePart = {
      inlineData: {
        data: req.file.buffer.toString("base64"),
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

    const responsePromise = modelGemini.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }, imagePart] }],
      generationConfig: { responseMimeType: "application/json" }
    });
    
    const result = await callWithTimeout(responsePromise);
    const text = result.response.text();

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        return res.status(500).json({ eroare: "AI nu a returnat JSON valid." });
      }
      try {
        parsed = JSON.parse(jsonMatch[0]);
      } catch (e2) {
        return res.status(500).json({ eroare: "AI nu a returnat JSON valid." });
      }
    }

    if (!Array.isArray(parsed)) {
       parsed = [parsed]; // Fallback in caz ca returneaza obiect in loc de array
    }

    res.json(parsed);
  } catch (error) {
    console.error("Eroare Gemini structurat:", error.message);
    res.status(500).json({ eroare: "Eroare la procesarea imaginii prin Gemini." });
  }
});

// ==========================================
// RUTA 2: CHAT CONVERSAȚIONAL (GEMINI)
// Securizată cu requireAuth
// ==========================================
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    let { mesaj, mesaje, caloriiConsumate, caloriiTinta, proteineConsumate, proteineTinta } = req.body;

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
- Calorii: a mâncat ${caloriiConsumate || 0} dintr-o țintă de ${caloriiTinta || 2000} kcal.
- Proteine: a mâncat ${proteineConsumate || 0}g dintr-o țintă de ${proteineTinta || 150}g.

Instrucțiuni de formatare și stil:
1. Folosește emoji-uri relevante la începutul propozițiilor sau ideilor importante (de exemplu 🥗, 🔥, 🥩, 💡, ✅).
2. Structurează răspunsul cu bullet points dacă oferi mai mult de 2 sugestii sau opțiuni de mese.
3. Răspunde concis, clar și la obiect. Poți folosi maximum 6-8 propoziții dacă utilizatorul cere explicații detaliate sau planuri de mese.

Sarcina ta: Răspunde prietenos, ținând cont de istoricul discuției și de caloriile/proteinele rămase astăzi.`;

    let contents = [];
    if (Array.isArray(mesaje) && mesaje.length > 0) {
      const istoric = mesaje.slice(-10);
      contents = istoric.map((m, idx) => {
        let role = m.role === 'user' || m.sender === 'user' ? 'user' : 'model';
        let text = m.text || m.content || '';
        if (idx === istoric.length - 1) text = ultimulMesaj;
        return { role, parts: [{ text }] };
      });
    } else {
      contents = [{ role: 'user', parts: [{ text: ultimulMesaj }] }];
    }

    contents.unshift({ role: 'user', parts: [{ text: systemPrompt }] });
    contents.splice(1, 0, { role: 'model', parts: [{ text: "Am înțeles contextul și regulile NutriAI. Cu ce te pot ajuta?" }] });

    // Filtrăm și unim mesajele consecutive cu același rol (user/model) pentru a respecta cerința strictă Gemini API
    const validContents = [];
    for (const item of contents) {
      if (!item.parts || !item.parts[0] || !item.parts[0].text.trim()) continue;
      if (validContents.length > 0 && validContents[validContents.length - 1].role === item.role) {
        validContents[validContents.length - 1].parts[0].text += "\n\n" + item.parts[0].text;
      } else {
        validContents.push({ role: item.role, parts: [{ text: item.parts[0].text }] });
      }
    }

    const responsePromise = modelGemini.generateContent({ contents: validContents });
    const result = await callWithTimeout(responsePromise);
    const raspunsText = result.response.text();
    
    res.json({ raspuns: raspunsText });
    
  } catch (error) {
    console.error("Eroare la generarea chat-ului Gemini:", error);
    res.status(500).json({ raspuns: `Eroare AI: ${error.message || "Problema de conexiune cu serverul AI. Mai încearcă!"}` });
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
    
    res.json({ caloriiTinta: Math.round(caloriiTinta), proteineTinta });
    
  } catch (error) {
    console.error("Eroare la calculul profilului:", error.message);
    res.status(500).json({ eroare: "Îmi pare rău, am întâmpinat o problemă la calcul. Mai încearcă!" });
  }
});

// ==========================================
// HANDLER GLOBAL DE ERORI
// ==========================================
app.use((err, req, res, next) => {
  console.error("Eroare globală:", err.message);
  if (err.message.includes('Tip fișier nepermis')) {
    return res.status(415).json({ eroare: err.message });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
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