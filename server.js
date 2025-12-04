import express from 'express';
import dotenv from 'dotenv';
import axios from "axios";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

app.use(express.json());

app.use(cors({
  origin: [
    "http://localhost:5173"   // ton frontend local
  ]
}));

// --- Scopes Google ---
const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/contacts.readonly",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/calendar.readonly",
].join(" ");

// ----- SUPABASE CLIENT -----
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ----- AES-256-GCM ENCRYPT -----
function encrypt(text) {
  const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  return iv.toString("base64") + "." + authTag + "." + encrypted;
}


// ------------------------------------------------
// 🔵 ROUTE 1 — /auth/google
// ------------------------------------------------
app.get('/auth/google', (req, res) => {

  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).send("Missing user_id.");

  const redirect = "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + process.env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + encodeURIComponent(process.env.GOOGLE_REDIRECT_URI) +
    "&response_type=code" +
    "&access_type=offline" +
    "&prompt=consent" +
    "&scope=" + encodeURIComponent(GOOGLE_SCOPES) +
    "&state=" + user_id; // on garde user_id dans state pour le callback

  return res.redirect(redirect);
});


// ------------------------------------------------
// 🔵 ROUTE 2 — Google OAuth Callback
// ------------------------------------------------
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  const user_id = req.query.state; // <<< IMPORTANT : on récupère le state

  if (!code) return res.status(400).send("Missing code.");
  if (!user_id) return res.status(400).send("Missing user_id (state).");

  try {
    // 1) Échange du code contre token Google
    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      },
      { headers: { "Content-Type": "application/json" } }
    );

    const {
      access_token,
      refresh_token,
      expires_in,
      scope
    } = tokenRes.data;

    const expires_at = Math.floor(Date.now() / 1000) + expires_in;

    // Chiffrement AES
    const access_encrypted = encrypt(access_token);
    const refresh_encrypted = refresh_token ? encrypt(refresh_token) : null;

    // 3) Sauvegarde dans Supabase
    const { error } = await supabase
      .from("oauth_tokens")
      .insert({
        user_id,
        provider: "google",
        access_token_enc: access_encrypted,
        refresh_token_enc: refresh_encrypted,
        expires_at,
        scope,
        meta: tokenRes.data
      });

    if (error) throw error;

    return res.send("Google OAuth OK ! Tokens enregistrés ✔");
  }
  catch (err) {
    console.error("OAuth ERROR:", err.response?.data || err);
    return res.status(500).send("Erreur Google OAuth (voir console backend)");
  }
});

// Déchiffrement AES-256-GCM
function decrypt(encrypted) {
  const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");
  const [ivB64, tagB64, valueB64] = encrypted.split(".");

  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const value = Buffer.from(valueB64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(value, undefined, "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}
// ------------------------------------------------
// 🔐 Route interne : /google/get-access-token
// ------------------------------------------------
app.get("/google/get-access-token", async (req, res) => {

  const user_id = req.query.user_id;
  if (!user_id) {
    return res.status(400).json({ error: "Missing user_id" });
  }

  // Lire les tokens chiffrés
  const { data, error } = await supabase
    .from("oauth_tokens")
    .select("*")
    .eq("user_id", user_id)
    .eq("provider", "google")
    .single();

  if (error) return res.status(500).json(error);

  // Déchiffrer
  const access_token = decrypt(data.access_token_enc);
  const refresh_token = decrypt(data.refresh_token_enc);

  // Retourner SIMPLE
  return res.json({
    access_token,
    refresh_token,
    expires_at: data.expires_at
  });
});
// ------------------------------------------------
// SERVEUR
// ------------------------------------------------
// ------------------------------------------------
// 🔐 ROUTE N8N POUR RÉCUPÉRER LES TOKENS GOOGLE
// ------------------------------------------------
app.get("/internal/google-tokens", async (req, res) => {
  const apiKey = req.headers["x-api-key"];

  // Vérification sécurité
  if (apiKey !== process.env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: "Missing user_id" });

  const { data, error } = await supabase
    .from("oauth_tokens")
    .select("*")
    .eq("user_id", user_id)
    .eq("provider", "google")
    .single();

  if (error) return res.status(500).json(error);

  res.json({
    access_token_enc: data.access_token_enc,
    refresh_token_enc: data.refresh_token_enc,
    expires_at: data.expires_at,
    scope: data.scope,
  });
});
// ------------------------------------------------
// 🔵 ROUTE — Get Access Token (avec refresh auto)
// ------------------------------------------------
app.get("/google/get-access-token", async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).send("Missing user_id");

  try {
    // 1. Récupération du token chiffré dans Supabase
    const { data, error } = await supabase
      .from("oauth_tokens")
      .select("*")
      .eq("user_id", user_id)
      .eq("provider", "google")
      .single();

    if (error || !data) return res.status(404).send("No token found");

    // 2. Déchiffrage
    const decrypt = (enc) => {
      const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");
      const [iv, tag, content] = enc.split(".").map(x => Buffer.from(x, "base64"));

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);

      let dec = decipher.update(content, null, "utf8");
      dec += decipher.final("utf8");
      return dec;
    };

    let accessToken = decrypt(data.access_token_enc);
    const refreshToken = decrypt(data.refresh_token_enc);

    const now = Math.floor(Date.now() / 1000);

    // 3. Si token expiré → rafraîchir
    if (data.expires_at < now) {
      console.log("🔄 Refreshing Google token...");

      const refreshRes = await axios.post(
        "https://oauth2.googleapis.com/token",
        {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          refresh_token: refreshToken,
          grant_type: "refresh_token"
        },
        { headers: { "Content-Type": "application/json" } }
      );

      accessToken = refreshRes.data.access_token;

      // 4. Ré-encryptage et sauvegarde
      const newAccessEnc = encrypt(accessToken);
      const newExpiresAt = Math.floor(Date.now() / 1000) + refreshRes.data.expires_in;

      await supabase
        .from("oauth_tokens")
        .update({
          access_token_enc: newAccessEnc,
          expires_at: newExpiresAt
        })
        .eq("user_id", user_id)
        .eq("provider", "google");
    }

    // 5. Retourner un vrai token
    return res.json({ access_token: accessToken });

  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error");
  }
});
app.listen(process.env.PORT || 3000, () => {
  console.log("🚀 Serveur backend lancé sur http://localhost:" + process.env.PORT);
});
// ------------------------------------------------
// 🟢 ROUTE 3 — Obtenir un access_token valide
// ------------------------------------------------
app.get('/google/get-access-token', async (req, res) => {
  const user_id = req.query.user_id;

  if (!user_id) return res.status(400).send("Missing user_id");

  try {
    // 1️⃣ Récupérer les tokens stockés
    const { data, error } = await supabase
      .from("oauth_tokens")
      .select("*")
      .eq("user_id", user_id)
      .eq("provider", "google")
      .single();

    if (error || !data) return res.status(400).send("No Google tokens found for this user.");

    // infos de la DB
    const encrypted_access = data.access_token_enc;
    const encrypted_refresh = data.refresh_token_enc;
    const expires_at = data.expires_at;

    // fonction pour déchiffrer
    function decrypt(payload) {
      if (!payload) return null;
      const [ivB64, tagB64, contentB64] = payload.split(".");
      const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");
      const iv = Buffer.from(ivB64, "base64");
      const tag = Buffer.from(tagB64, "base64");

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(contentB64, "base64", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    }

    let access_token = decrypt(encrypted_access);
    const refresh_token = decrypt(encrypted_refresh);

    // 2️⃣ Vérifier si l'access_token est expiré
    const now = Math.floor(Date.now() / 1000);

    if (now >= expires_at) {
      console.log("🔄 Access token expiré → on rafraîchit...");

      // 3️⃣ Rafraîchir l'access token
      const refreshRes = await axios.post(
        "https://oauth2.googleapis.com/token",
        {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          refresh_token,
          grant_type: "refresh_token",
        },
        { headers: { "Content-Type": "application/json" } }
      );

      access_token = refreshRes.data.access_token;
      const new_expires_at = Math.floor(Date.now() / 1000) + refreshRes.data.expires_in;

      // 4️⃣ Stocker les nouveaux tokens chiffrés
      const { error: updateErr } = await supabase
        .from("oauth_tokens")
        .update({
          access_token_enc: encrypt(access_token),
          expires_at: new_expires_at,
        })
        .eq("user_id", user_id)
        .eq("provider", "google");

      if (updateErr) throw updateErr;
    }

    // 5️⃣ Retourner un access_token valide
    return res.json({ access_token });
  }
  catch (err) {
    console.error(err.response?.data || err);
    return res.status(500).send("Erreur lors de la récupération du token.");
  }
});
import cors from "cors";
