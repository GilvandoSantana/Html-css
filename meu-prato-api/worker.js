// Meu Prato: API de contas, dados e fotos (Cloudflare Workers + D1). Sistema isolado, só do Meu Prato.
const enc = new TextEncoder();
const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
async function sha(s) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))); }
const tokenNew = () => hex(crypto.getRandomValues(new Uint8Array(32)));
async function pbkdf2(pass, salt, iter) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, k, 256));
}
async function hashPass(pass, env) {
  const iter = Math.min(100000, Math.max(1000, parseInt(env.PBKDF2_ITER) || 100000));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${iter}$${hex(salt)}$${hex(await pbkdf2(pass, salt, iter))}`;
}
async function verifyPass(pass, stored) {
  const [, it, salt, h] = String(stored).split("$");
  const got = await pbkdf2(pass, unhex(salt), parseInt(it));
  const want = unhex(h);
  let d = 0; for (let i = 0; i < want.length; i++) d |= got[i] ^ want[i];
  return d === 0;
}

const fails = new Map();
const limited = (k) => { const f = fails.get(k); return !!f && Date.now() - f.ts < 600000 && f.n >= 8; };
const failed = (k) => { const f = fails.get(k); if (!f || Date.now() - f.ts >= 600000) fails.set(k, { n: 1, ts: Date.now() }); else f.n++; };

function cors(req, env) {
  const origins = String(env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const o = req.headers.get("origin") || "";
  const h = { Vary: "Origin", "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS", "Access-Control-Allow-Headers": "authorization,content-type", "Access-Control-Max-Age": "86400" };
  if (origins.includes(o)) h["Access-Control-Allow-Origin"] = o;
  return h;
}
const json = (req, env, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...cors(req, env) } });
const err = (req, env, status, msg) => json(req, env, { erro: msg }, status);

const USER_RE = /^[a-z0-9_.-]{3,30}$/;

export default {
  async fetch(req, env) {
    try { return await handle(req, env); }
    catch (e) { console.error(e); return err(req, env, 500, "Erro no servidor."); }
  },
};

async function handle(req, env) {
  const q = async (text, params = []) => (await env.DB.prepare(text.replace(/\$(\d+)/g, "?$1")).bind(...params).all()).results || [];
  const url = new URL(req.url), p = url.pathname, method = req.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req, env) });
  if (p === "/" || p === "/health") return json(req, env, { ok: true });
  if (!p.startsWith("/api/")) return err(req, env, 404, "Não encontrado");
  if (Number(req.headers.get("content-length") || 0) > 2000000) return err(req, env, 413, "Arquivo grande demais");
  const body = async () => { try { return await req.json(); } catch { return {}; } };
  const ip = (req.headers.get("cf-connecting-ip") || "x").trim();

  const newSession = async (uid) => {
    const t = tokenNew();
    await q(`INSERT INTO sessions(th, uid, created) VALUES($1,$2,$3)`, [await sha(t), uid, Date.now()]);
    return t;
  };
  const pub = (u) => ({ username: u.username, nome: u.nome, sexo: u.sexo });

  if (p === "/api/register" && method === "POST") {
    const b = await body();
    const username = String(b.username || "").toLowerCase().trim(), pass = String(b.pass || ""), nome = String(b.nome || "").trim().slice(0, 40), sexo = b.sexo;
    if (!USER_RE.test(username)) return err(req, env, 400, "Usuário: 3 a 30 letras minúsculas, números, ponto, hífen ou _.");
    if (pass.length < 6 || pass.length > 100) return err(req, env, 400, "A senha precisa ter de 6 a 100 caracteres.");
    if (!nome) return err(req, env, 400, "Informe seu nome.");
    if (sexo !== "f" && sexo !== "m") return err(req, env, 400, "Escolha Feminino ou Masculino.");
    if (limited("r" + ip)) return err(req, env, 429, "Muitas tentativas. Tente em alguns minutos.");
    failed("r" + ip);
    if ((await q(`SELECT 1 FROM users WHERE username=$1`, [username])).length) return err(req, env, 409, "Esse usuário já existe. Escolha outro.");
    const h = await hashPass(pass, env);
    const rows = await q(`INSERT INTO users(username, pass, nome, sexo, created) VALUES($1,$2,$3,$4,$5) RETURNING id`, [username, h, nome, sexo, Date.now()]);
    return json(req, env, { token: await newSession(Number(rows[0].id)), user: { username, nome, sexo } });
  }
  if (p === "/api/login" && method === "POST") {
    const b = await body(), username = String(b.username || "").toLowerCase().trim(), k = "l" + ip + username;
    if (limited(k)) return err(req, env, 429, "Muitas tentativas. Tente em alguns minutos.");
    const u = (await q(`SELECT * FROM users WHERE username=$1`, [username]))[0];
    if (!u || !(await verifyPass(String(b.pass || ""), u.pass))) { failed(k); return err(req, env, 401, "Usuário ou senha incorretos."); }
    fails.delete(k);
    return json(req, env, { token: await newSession(Number(u.id)), user: pub(u) });
  }

  const m0 = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get("authorization") || "");
  let me = null;
  if (m0) {
    const r = (await q(`SELECT u.id, u.username, u.nome, u.sexo, s.created FROM sessions s JOIN users u ON u.id = s.uid WHERE s.th = $1`, [await sha(m0[1])]))[0];
    if (r && Date.now() - Number(r.created) <= 180 * 86400000) me = r;
  }
  if (!me) return err(req, env, 401, "Sessão expirada. Entre de novo.");
  const uid = Number(me.id);

  if (p === "/api/state" && method === "GET") {
    const docs = {};
    for (const r of await q(`SELECT name, json FROM docs WHERE uid=$1`, [uid])) docs[r.name] = r.json;
    return json(req, env, { user: pub(me), docs });
  }
  if (p === "/api/logout" && method === "POST") {
    await q(`DELETE FROM sessions WHERE th=$1`, [await sha(m0[1])]);
    return json(req, env, { ok: true });
  }
  if (p === "/api/profile" && method === "PUT") {
    const b = await body(), nome = String(b.nome || "").trim().slice(0, 40), sexo = b.sexo;
    if (!nome || (sexo !== "f" && sexo !== "m")) return err(req, env, 400, "Dados inválidos.");
    await q(`UPDATE users SET nome=$1, sexo=$2 WHERE id=$3`, [nome, sexo, uid]);
    return json(req, env, { user: { username: me.username, nome, sexo } });
  }
  if (p === "/api/password" && method === "POST") {
    const b = await body(), u = (await q(`SELECT pass FROM users WHERE id=$1`, [uid]))[0];
    if (!(await verifyPass(String(b.old || ""), u.pass))) return err(req, env, 401, "Senha atual incorreta.");
    const np = String(b.new || "");
    if (np.length < 6 || np.length > 100) return err(req, env, 400, "A nova senha precisa ter de 6 a 100 caracteres.");
    await q(`UPDATE users SET pass=$1 WHERE id=$2`, [await hashPass(np, env), uid]);
    return json(req, env, { ok: true });
  }
  if (p === "/api/account" && method === "DELETE") {
    const b = await body(), u = (await q(`SELECT pass FROM users WHERE id=$1`, [uid]))[0];
    if (!(await verifyPass(String(b.pass || ""), u.pass))) return err(req, env, 401, "Senha incorreta.");
    for (const t of ["photos", "docs", "sessions"]) await q(`DELETE FROM ${t} WHERE uid=$1`, [uid]);
    await q(`DELETE FROM users WHERE id=$1`, [uid]);
    return json(req, env, { ok: true });
  }
  let m = /^\/api\/doc\/(core|log_\d{4}-\d{2})$/.exec(p);
  if (m && method === "PUT") {
    const b = await body();
    if (typeof b.json !== "string" || b.json.length > 900000) return err(req, env, 400, "Dados inválidos.");
    if (m[1] === "core") {
      const last = (await q(`SELECT t FROM doc_hist WHERE uid=$1 AND name=$2 ORDER BY t DESC LIMIT 1`, [uid, "core"]))[0];
      if (!last || Date.now() - Number(last.t) > 3 * 3600000) {
        const cur = (await q(`SELECT json FROM docs WHERE uid=$1 AND name=$2`, [uid, "core"]))[0];
        if (cur) {
          await q(`INSERT INTO doc_hist(uid, name, json, t) VALUES($1,$2,$3,$4)`, [uid, "core", cur.json, Date.now()]);
          await q(`DELETE FROM doc_hist WHERE uid=$1 AND name=$2 AND t NOT IN (SELECT t FROM doc_hist WHERE uid=$1 AND name=$2 ORDER BY t DESC LIMIT 40)`, [uid, "core"]);
        }
      }
    }
    await q(`INSERT INTO docs(uid, name, json, t) VALUES($1,$2,$3,$4) ON CONFLICT(uid, name) DO UPDATE SET json=excluded.json, t=excluded.t`, [uid, m[1], b.json, Date.now()]);
    return json(req, env, { ok: true });
  }
  if (p === "/api/photos" && method === "GET") {
    const rows = await q(`SELECT id, pose, d, ts, t FROM photos WHERE uid=$1 ORDER BY d, ts`, [uid]);
    return json(req, env, rows.map((r) => ({ id: r.id, pose: r.pose, d: r.d, at: Number(r.ts), t: r.t })));
  }
  if (p === "/api/photos" && method === "POST") {
    const b = await body();
    if (!/^[a-z0-9]{4,40}$/i.test(String(b.id)) || !["frente", "lado", "costas"].includes(b.pose) || !/^\d{4}-\d{2}-\d{2}$/.test(String(b.d))) return err(req, env, 400, "Dados inválidos.");
    if (!/^data:image\/jpeg;base64,/.test(String(b.u)) || !/^data:image\/jpeg;base64,/.test(String(b.t)) || b.u.length > 900000 || b.t.length > 120000) return err(req, env, 400, "Imagem inválida ou grande demais.");
    const n = Number((await q(`SELECT COUNT(*) AS n FROM photos WHERE uid=$1`, [uid]))[0].n);
    if (n >= 300) return err(req, env, 400, "Limite de 300 fotos atingido.");
    await q(`INSERT INTO photos(id, uid, pose, d, ts, u, t) VALUES($1,$2,$3,$4,$5,$6,$7)`, [b.id, uid, b.pose, b.d, Date.now(), b.u, b.t]);
    return json(req, env, { ok: true });
  }
  m = /^\/api\/photos\/([a-z0-9]{4,40})$/i.exec(p);
  if (m && method === "GET") {
    const r = (await q(`SELECT u FROM photos WHERE id=$1 AND uid=$2`, [m[1], uid]))[0];
    return r ? json(req, env, { u: r.u }) : err(req, env, 404, "Foto não encontrada.");
  }
  if (m && method === "DELETE") { await q(`DELETE FROM photos WHERE id=$1 AND uid=$2`, [m[1], uid]); return json(req, env, { ok: true }); }
  return err(req, env, 404, "Não encontrado");
}
