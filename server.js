import express from "express";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: ["http://localhost:5173"], // ton frontend
  })
);

// ------------------------------------------------------
// 🔐 CRYPTO utils
// ------------------------------------------------------
function encrypt(text) {
  const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");

  const tag = cipher.getAuthTag().toString("base64");
  return iv.toString("base64") + "." + tag + "." + encrypted;
}

function decrypt(enc) {
  if (!enc) return null;
  const key = Buffer.from(process.env.TOKEN_ENC_KEY, "base64");

  const [ivB64, tagB64, contentB64] = enc.split(".");
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const content = Buffer.from(contentB64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(content, null, "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ------------------------------------------------------
// 🔌 SUPABASE
// ------------------------------------------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ------------------------------------------------------
// 🔵 ROUTE 1 — Google OAuth Redirect
// ------------------------------------------------------
const GOOGLE_SCOPES = [
  // User info
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",

  // Gmail
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/gmail.compose",

  // Contacts
  "https://www.googleapis.com/auth/contacts.readonly",
  "https://www.googleapis.com/auth/contacts",

  // Calendar
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events",
].join(" ");

app.get("/auth/google", (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).send("Missing user_id");

  const redirect =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" +
    process.env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" +
    encodeURIComponent(process.env.GOOGLE_REDIRECT_URI) +
    "&response_type=code" +
    "&access_type=offline" +
    "&prompt=consent" +
    "&scope=" +
    encodeURIComponent(GOOGLE_SCOPES) +
    "&state=" +
    user_id;

  res.redirect(redirect);
});

// ------------------------------------------------------
// 🔵 ROUTE 2 — Google Callback
// ------------------------------------------------------
app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code;
  const user_id = req.query.state;

  if (!code) return res.status(400).send("Missing code");
  if (!user_id) return res.status(400).send("Missing user_id");

  try {
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

    const access_token = tokenRes.data.access_token;
    const refresh_token = tokenRes.data.refresh_token;
    const expires_at =
      Math.floor(Date.now() / 1000) + tokenRes.data.expires_in;

    await supabase.from("oauth_tokens").upsert({
      user_id,
      provider: "google",
      access_token_enc: encrypt(access_token),
      refresh_token_enc: refresh_token ? encrypt(refresh_token) : null,
      expires_at,
      scope: tokenRes.data.scope,
      meta: tokenRes.data,
    });

    res.send("Google OAuth OK ✔ Tokens enregistrés !");
  } catch (err) {
    console.error("OAuth ERROR:", err.response?.data || err);
    res.status(500).send("Erreur OAuth");
  }
});

// ------------------------------------------------------
// 🟢 ROUTE 3 — Get Access Token (Auto-refresh)
// ------------------------------------------------------
app.get("/google/get-access-token", async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).send("Missing user_id");

  try {
    const { data, error } = await supabase
      .from("oauth_tokens")
      .select("*")
      .eq("user_id", user_id)
      .eq("provider", "google")
      .single();

    if (error || !data)
      return res.status(400).send("No Google tokens found");

    let access = decrypt(data.access_token_enc);
    const refresh = decrypt(data.refresh_token_enc);
    const now = Math.floor(Date.now() / 1000);

    if (now >= data.expires_at) {
      console.log("🔄 Token expiré → Refresh...");

      const refreshRes = await axios.post(
        "https://oauth2.googleapis.com/token",
        {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          refresh_token: refresh,
          grant_type: "refresh_token",
        },
        { headers: { "Content-Type": "application/json" } }
      );

      access = refreshRes.data.access_token;

      await supabase
        .from("oauth_tokens")
        .update({
          access_token_enc: encrypt(access),
          expires_at:
            Math.floor(Date.now() / 1000) + refreshRes.data.expires_in,
        })
        .eq("user_id", user_id)
        .eq("provider", "google");
    }

    res.json({ access_token: access });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error fetching token");
  }
});
// 🔵 ROUTE 4 — Force Reconnection Google
app.get("/auth/google/refresh", (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).send("Missing user_id");

  // Redirige vers ta route Google OAuth existante
  res.redirect(`/auth/google?user_id=${user_id}`);
});
// ------------------------------------------------------
// 🟢 ROUTE INTERNE N8N
// ------------------------------------------------------
app.get("/internal/google-tokens", async (req, res) => {
  if (req.headers["x-api-key"] !== process.env.INTERNAL_API_KEY)
    return res.status(401).json({ error: "Unauthorized" });

  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: "Missing user_id" });

  const { data, error } = await supabase
    .from("oauth_tokens")
    .select("*")
    .eq("user_id", user_id)
    .eq("provider", "google")
    .single();

  if (error) return res.status(500).json(error);

  res.json(data);
});

// ------------------------------------------------------
// 🚀 SERVER
// ------------------------------------------------------
app.listen(process.env.PORT || 3000, () => {
  console.log(
    "🚀 Backend running on port " + (process.env.PORT || 3000)
  );
});
