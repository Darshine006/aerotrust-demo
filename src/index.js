const encoder = new TextEncoder();
let jwksCache = { expires: 0, keys: null };

const json = (data, status = 200) => new Response(JSON.stringify(data, null, 2), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});

function hexToBytes(hex) {
  if (!/^[a-f0-9]{64}$/i.test(hex)) return null;
  return new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));
}

async function verifyGithubSignature(secret, body, header) {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const signature = hexToBytes(header.slice(7));
  if (!signature) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, signature, encoder.encode(body));
}

function b64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function getAccessKeys(teamDomain) {
  const domain = teamDomain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (!/^[a-z0-9.-]+$/i.test(domain)) throw new Error("Invalid ACCESS_TEAM_DOMAIN");
  if (jwksCache.keys && jwksCache.expires > Date.now()) return jwksCache.keys;
  const response = await fetch(`https://${domain}/cdn-cgi/access/certs`, { cf: { cacheTtl: 300 } });
  if (!response.ok) throw new Error("Unable to retrieve Cloudflare Access signing keys");
  const data = await response.json();
  jwksCache = { keys: data.keys || [], expires: Date.now() + 5 * 60 * 1000 };
  return jwksCache.keys;
}

async function verifyAccess(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return false;
  const token = request.headers.get("CF-Access-Jwt-Assertion");
  if (!token) return false;
  try {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
    if (!encodedHeader || !encodedPayload || !encodedSignature) return false;
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(encodedHeader)));
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(encodedPayload)));
    if (header.alg !== "RS256" || !header.kid) return false;
    const domain = env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//, "").replace(/\/$/, "");
    const issuer = `https://${domain}`;
    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== issuer || !audience.includes(env.ACCESS_AUD) || !payload.exp || payload.exp <= now || (payload.nbf && payload.nbf > now)) return false;
    const jwk = (await getAccessKeys(domain)).find(k => k.kid === header.kid);
    if (!jwk) return false;
    const publicKey = await crypto.subtle.importKey("jwk", jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey,
      b64urlToBytes(encodedSignature), encoder.encode(`${encodedHeader}.${encodedPayload}`));
  } catch { return false; }
}

function evaluatePolicy({ isFork, files }) {
  const normalized = files.map(f => String(f).toLowerCase());
  const workflow = normalized.filter(p => p.startsWith(".github/workflows/") || p.startsWith(".github/actions/") || p.endsWith("/action.yml") || p === "action.yml" || p.endsWith("/action.yaml") || p === "action.yaml");
  const sensitive = normalized.filter(p => /(^|\/)(terraform|infra|infrastructure|kubernetes|k8s|helm)(\/|$)/.test(p) || /(^|\/)(dockerfile|docker-compose\.ya?ml)$/.test(p) || /(^|\/)(deploy|deployment|release)(\.|\/|$)/.test(p));
  if (isFork && workflow.length) return { decision: "BLOCK", reason: "An external fork changed privileged GitHub Actions workflow or action configuration. Untrusted contributions cannot modify the CI/CD trust boundary.", signals: { external_fork: true, workflow_change: true, sensitive_change: sensitive.length > 0 } };
  if (isFork && sensitive.length) return { decision: "REVIEW", reason: "An external fork changed deployment or infrastructure configuration. Require a trusted maintainer review before these changes are accepted.", signals: { external_fork: true, workflow_change: false, sensitive_change: true } };
  if (!files.length) return { decision: "REVIEW", reason: "No changed-file evidence was available. Fail closed and request manual review.", signals: { external_fork: !!isFork, workflow_change: false, sensitive_change: false } };
  return { decision: "ALLOW", reason: "The contribution contains no high-risk path changes under the current policy. This is a policy result, not an automatic merge or deployment approval.", signals: { external_fork: !!isFork, workflow_change: workflow.length > 0, sensitive_change: sensitive.length > 0 } };
}

async function githubFiles(repo, number, token) {
  const files = [];
  for (let page = 1; page <= 30; page++) {
    const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AeroTrust-Worker" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(`https://api.github.com/repos/${repo}/pulls/${number}/files?per_page=100&page=${page}`, { headers });
    if (!response.ok) throw new Error(`GitHub changed-files API returned ${response.status}`);
    const batch = await response.json();
    files.push(...batch.map(item => item.filename));
    if (batch.length < 100) return files;
  }
  throw new Error("Pull request changed-file list exceeded the configured safety limit");
}

async function saveDecision(env, data) {
  const result = await env.DB.prepare(`INSERT OR IGNORE INTO decisions
    (delivery_id, event_type, repository, pr_number, contributor, source_type, changed_files, decision, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(data.delivery_id, data.event_type, data.repository, data.pr_number, data.contributor,
      data.source_type, JSON.stringify(data.changed_files || []), data.decision, data.reason).run();
  return (result.meta?.changes || 0) > 0;
}

async function postPrComment(repo, number, data, token) {
  if (!token) return { posted: false, reason: "GITHUB_TOKEN not configured" };
  const body = `### AeroTrust contribution policy: ${data.decision}\n\n${data.reason}\n\n**Signals**\n- External fork: ${data.signals.external_fork}\n- Workflow change: ${data.signals.workflow_change}\n- Sensitive infrastructure change: ${data.signals.sensitive_change}\n\n_AeroTrust records a risk decision only. It does not automatically merge the pull request or grant deployment permissions._`;
  const response = await fetch(`https://api.github.com/repos/${repo}/issues/${number}/comments`, {
    method: "POST", headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "AeroTrust-Worker" },
    body: JSON.stringify({ body })
  });
  if (!response.ok) return { posted: false, reason: `GitHub comment API returned ${response.status}` };
  return { posted: true };
}

async function handleWebhook(request, env) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 1024 * 1024) return json({ error: "Webhook payload too large" }, 413);
  const body = await request.text();
  if (encoder.encode(body).length > 1024 * 1024) return json({ error: "Webhook payload too large" }, 413);
  if (!await verifyGithubSignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256"))) return json({ error: "Invalid GitHub signature" }, 401);
  const event = request.headers.get("X-GitHub-Event");
  const deliveryId = request.headers.get("X-GitHub-Delivery");
  if (!deliveryId) return json({ error: "Missing GitHub delivery identifier" }, 400);
  if (event !== "pull_request") return json({ ok: true, ignored: event });
  let payload;
  try { payload = JSON.parse(body); } catch { return json({ error: "Invalid JSON payload" }, 400); }
  if (!["opened", "synchronize", "reopened", "ready_for_review"].includes(payload.action)) return json({ ok: true, ignored_action: payload.action });
  const pr = payload.pull_request;
  const repo = payload.repository?.full_name;
  if (!pr?.number || !repo) return json({ error: "Incomplete pull request payload" }, 400);
  if (env.GITHUB_REPOSITORY && repo.toLowerCase() !== env.GITHUB_REPOSITORY.toLowerCase()) return json({ error: "Repository is not allowlisted" }, 403);
  const isFork = !!pr.head?.repo?.full_name && pr.head.repo.full_name.toLowerCase() !== (pr.base?.repo?.full_name || repo).toLowerCase();
  let files = [];
  let result;
  try {
    files = await githubFiles(repo, pr.number, env.GITHUB_TOKEN);
    result = evaluatePolicy({ isFork, files });
  } catch (error) {
    result = { decision: "REVIEW", reason: `AeroTrust could not verify the complete changed-file list (${error.message}). The request is held for manual review rather than trusted by default.`, signals: { external_fork: isFork, workflow_change: false, sensitive_change: false } };
  }
  const inserted = await saveDecision(env, {
    delivery_id: deliveryId, event_type: `pull_request.${payload.action}`, repository: repo,
    pr_number: pr.number, contributor: pr.user?.login || "unknown", source_type: isFork ? "external_fork" : "same_repository",
    changed_files: files, decision: result.decision, reason: result.reason
  });
  if (!inserted) return json({ ok: true, duplicate: true, delivery_id: deliveryId });
  const comment = await postPrComment(repo, pr.number, result, env.GITHUB_TOKEN);
  return json({ ok: true, project: "AeroTrust", delivery_id: deliveryId, decision: result.decision,
    reason: result.reason, signals: result.signals, repository: repo, pull_request: pr.number,
    changed_files: files, github_comment: comment });
}


const SESSION_HOURS = 12;
const PBKDF2_ITERATIONS = 310000;
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sha(value){return hex(await crypto.subtle.digest("SHA-256",encoder.encode(value)));}
function token(){return [...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,"0")).join("");}
async function pwHash(password,salt){
 const key=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
 return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:encoder.encode(salt),iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},key,256));
}
function cookie(req){const s=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("aerotrust_session="));return s?decodeURIComponent(s.slice("aerotrust_session=".length)):"";}
function setCookie(t,age=43200){return "aerotrust_session="+encodeURIComponent(t)+"; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age="+age;}
async function bootstrap(env,email,password){
 const n=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
 if(Number(n?.n||0)!==0||!env.ADMIN_EMAIL||!env.ADMIN_PASSWORD||email!==env.ADMIN_EMAIL.toLowerCase()||password!==env.ADMIN_PASSWORD)return;
 const salt=token(),hash=await pwHash(password,salt);
 await env.DB.prepare("INSERT INTO users(email,password_salt,password_hash,role) VALUES(?,?,?,'admin')").bind(email,salt,hash).run();
}
async function login(req,env){
 let b;try{b=await req.json();}catch{return json({error:"Invalid request"},400);}
 const email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<12||password.length>256)return json({error:"Enter a valid email and a password of at least 12 characters."},400);
 let u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
 if(!u){await bootstrap(env,email,password);u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();}
 if(!u||await pwHash(password,u.password_salt)!==u.password_hash)return json({error:"Invalid email or password."},401);
 const t=token(),h=await sha(t),expires=new Date(Date.now()+SESSION_HOURS*3600000).toISOString();
 await env.DB.prepare("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES(?,?,?)").bind(u.id,h,expires).run();
 return new Response(JSON.stringify({ok:true,user:{email:u.email,role:u.role}}),{headers:{"content-type":"application/json","cache-control":"no-store","set-cookie":setCookie(t)}});
}
async function logout(req,env){const t=cookie(req);if(t)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(t)).run();return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json","set-cookie":setCookie("",0),"cache-control":"no-store"}});}
async function sessionUser(req,env){
 const t=cookie(req);if(!/^[a-f0-9]{64}$/.test(t))return null;
 return await env.DB.prepare("SELECT users.id,users.email,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND datetime(sessions.expires_at)>CURRENT_TIMESTAMP").bind(await sha(t)).first();
}
function loginPage(){
 return \`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AeroTrust · Sign in</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(ellipse at 50% 0,#203653,#0b1220 65%);color:#e8eef8;font:15px Inter,system-ui}.card{width:min(430px,calc(100% - 32px));padding:36px;background:#111c2c;border:1px solid #2b3d56;border-radius:20px;box-shadow:0 24px 80px #0007}.brand{display:flex;align-items:center;gap:12px;margin-bottom:30px}.mark{display:grid;place-items:center;width:48px;height:48px;background:#f5f7fb;color:#111c2c;border-radius:13px;font-size:25px;font-weight:800}.eyebrow{color:#79dfb4;font-size:11px;letter-spacing:1.5px;text-transform:uppercase}h1{margin:3px 0;font-size:25px}h2{margin-bottom:8px}p{color:#9fb0c8;line-height:1.6}.field{display:block;margin:18px 0 7px;color:#cbd6e5;font-size:13px}input{width:100%;padding:13px;background:#0b1423;border:1px solid #34445c;border-radius:9px;color:white;font:inherit}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:9px;background:#79e0b5;color:#092018;font-weight:750;font-size:15px;cursor:pointer}.error{color:#ff9999;min-height:20px;font-size:13px}.foot{text-align:center;color:#8294ad;font-size:12px;margin-top:24px}</style></head><body><main class="card"><div class="brand"><div class="mark">A</div><div><div class="eyebrow">Secure contribution gateway</div><h1>AeroTrust</h1></div></div><h2>Welcome back</h2><p>Sign in to review GitHub contribution risk, policy decisions and audit activity.</p><form id="login"><label class="field" for="email">Work email</label><input id="email" type="email" autocomplete="username" required placeholder="you@company.com"><label class="field" for="password">Password</label><input id="password" type="password" autocomplete="current-password" minlength="12" required placeholder="At least 12 characters"><div class="error" id="error" role="alert"></div><button>Sign in securely</button></form><div class="foot">AeroTrust · Security policy console</div></main><script>document.getElementById("login").addEventListener("submit",async e=>{e.preventDefault();const x=document.getElementById("error");x.textContent="Signing in…";try{const r=await fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email:document.getElementById("email").value,password:document.getElementById("password").value})});const d=await r.json();if(!r.ok)throw Error(d.error||"Sign in failed");location.href="/";}catch(err){x.textContent=err.message;}});</script></body></html>\`;
}

async function dashboard(env,user) {
  const result = await env.DB.prepare("SELECT * FROM decisions ORDER BY id DESC LIMIT 100").all();
  return new Response(renderDashboard(result.results || [], user), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

function renderDashboard(rows, user) {
  const esc = s => String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  const counts = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };
  rows.forEach(r => { if (counts[r.decision] !== undefined) counts[r.decision]++; });
  const records = rows.map(r => `<tr><td>${esc(r.created_at)}</td><td>${esc(r.repository)}</td><td>#${esc(r.pr_number)}</td><td>${esc(r.contributor)}</td><td>${esc(r.source_type)}</td><td><b class="${esc(r.decision).toLowerCase()}">${esc(r.decision)}</b></td><td>${esc(r.reason)}</td><td><code>${esc(r.delivery_id || "legacy")}</code></td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AeroTrust · Trust Console</title><style>
  *{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e8eef8;font:14px Inter,system-ui,sans-serif}header{padding:30px 6%;border-bottom:1px solid #263247;background:#111c2e}h1{margin:0;font-size:28px;letter-spacing:-.6px}header p{color:#a8b7cc;margin:8px 0 0}.tag{color:#8be0c0;font-size:11px;letter-spacing:1.4px;text-transform:uppercase}main{padding:28px 6%;max-width:1600px;margin:auto}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:20px 0 30px}.metric{background:#121e30;border:1px solid #26364e;border-radius:12px;padding:18px}.metric span{color:#9fb0c8}.metric strong{display:block;font-size:30px;margin-top:8px}.allow{color:#6ee7a8}.review{color:#f6c66d}.block{color:#ff8585}.tablewrap{overflow:auto;border:1px solid #26364e;border-radius:12px}table{width:100%;border-collapse:collapse;min-width:1050px;background:#111c2c}th,td{text-align:left;padding:13px;border-bottom:1px solid #263247;vertical-align:top}th{color:#9fb0c8;background:#17253a;font-size:12px;text-transform:uppercase;letter-spacing:.6px}td{max-width:300px;line-height:1.5}code{font-size:11px;color:#9fb0c8;overflow-wrap:anywhere}.note{color:#9fb0c8;margin-top:18px;line-height:1.6}.status{display:inline-block;border:1px solid #315a52;border-radius:20px;padding:5px 9px;color:#8be0c0;font-size:11px}@media(max-width:650px){.grid{grid-template-columns:1fr}main{padding:20px 4%}}
  </style></head><body><header><div class="tag">Cloudflare Workers · D1 · GitHub Webhooks · Zero Trust</div><h1>AeroTrust Trust Console</h1><p>Policy-based risk evaluation · Signed in as ${user.email}</p><button onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/')" style="float:right;background:#26364e;color:#e8eef8;padding:9px 14px;margin-top:-38px;width:auto">Sign out</button></header><main><span class="status">LIVE WEBHOOK AUDIT · AUTHENTICATED SESSION</span><section class="grid"><div class="metric"><span>ALLOW decisions</span><strong class="allow">${counts.ALLOW}</strong></div><div class="metric"><span>REVIEW decisions</span><strong class="review">${counts.REVIEW}</strong></div><div class="metric"><span>BLOCK decisions</span><strong class="block">${counts.BLOCK}</strong></div></section><h2>GitHub pull-request audit trail</h2><div style="display:flex;gap:10px;flex-wrap:wrap;margin:14px 0"><input id="q" placeholder="Search repository, contributor or reason" style="flex:1;min-width:220px;padding:11px;background:#111c2c;border:1px solid #34445c;border-radius:8px;color:#fff"><select id="f" style="padding:11px;background:#111c2c;border:1px solid #34445c;border-radius:8px;color:#fff"><option value="">All decisions</option><option>ALLOW</option><option>REVIEW</option><option>BLOCK</option></select></div><div class="tablewrap"><table><thead><tr><th>Received</th><th>Repository</th><th>PR</th><th>Author</th><th>Source</th><th>Decision</th><th>Policy rationale</th><th>Delivery ID</th></tr></thead><tbody>${records || "<tr><td colspan='8'>No verified GitHub pull-request events recorded yet.</td></tr>"}</tbody></table></div><p class="note">AeroTrust verifies GitHub webhook authenticity with HMAC-SHA256 and requires an authenticated application session for dashboard access. Cloudflare Access can be added as a second identity layer when enabled. ALLOW is not an automatic merge or deployment grant.</p></main><script>const q=document.getElementById('q'),f=document.getElementById('f');function filter(){document.querySelectorAll('tbody tr').forEach(r=>{const t=r.innerText.toLowerCase();r.hidden=!!((q.value&&!t.includes(q.value.toLowerCase()))||(f.value&&!t.includes(f.value.toLowerCase())));});}q.addEventListener('input',filter);f.addEventListener('change',filter);</script></body></html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return json({ok:true,service:"AeroTrust",webhook:"enabled",application_login:true,cloudflare_access:!!(env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD)});
    if (request.method === "POST" && url.pathname === "/webhook/github") {
      try { return await handleWebhook(request, env); } catch (error) { return json({ error: "Webhook processing failed", detail: error.message }, 500); }
    }
    if (request.method === "POST" && url.pathname === "/api/login") return login(request,env);
    if (request.method === "POST" && url.pathname === "/api/logout") return logout(request,env);
    if (url.pathname === "/" || url.pathname.startsWith("/api/")) {
      if(env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&!await verifyAccess(request,env))return json({error:"Cloudflare Access authentication required or invalid"},403);
      const user=await sessionUser(request,env);
      if(!user){if(request.method==="GET"&&url.pathname==="/")return new Response(loginPage(),{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});return json({error:"Application login required"},401);}
      if(request.method==="GET"&&url.pathname==="/")return dashboard(env,user);
      if(request.method==="GET"&&url.pathname==="/api/session")return json({ok:true,user:{email:user.email,role:user.role}});
      if(request.method==="GET"&&url.pathname==="/api/decisions"){const result=await env.DB.prepare("SELECT * FROM decisions ORDER BY id DESC LIMIT 100").all();return json(result.results||[]);}
    }
    return json({ error: "Not found" }, 404);
  }
};
