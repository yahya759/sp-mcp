export interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  IG_APP_ID: string;
  IG_APP_SECRET: string;
  MCP_BASE_URL: string;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function html(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS },
  });
}

function randomToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------- Supabase REST helpers (service role, bypasses RLS) ----------

function sbHeaders(env: Env) {
  return {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };
}

async function sbSelect(env: Env, table: string, query: string) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}?${query}`, {
    headers: sbHeaders(env),
  });
  if (!res.ok) throw new Error(`supabase select ${table} failed: ${await res.text()}`);
  return res.json();
}

async function sbInsert(env: Env, table: string, row: Record<string, unknown>) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: { ...sbHeaders(env), Prefer: "return=representation" },
    body: JSON.stringify(row),
  });
  if (!res.ok) throw new Error(`supabase insert ${table} failed: ${await res.text()}`);
  return res.json();
}

async function sbUpdate(env: Env, table: string, query: string, patch: Record<string, unknown>) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}?${query}`, {
    method: "PATCH",
    headers: { ...sbHeaders(env), Prefer: "return=representation" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error(`supabase update ${table} failed: ${await res.text()}`);
  return res.json();
}

// ---------- OAuth: /authorize (login + consent page) ----------

async function handleAuthorizeGet(url: URL): Promise<Response> {
  const params = url.searchParams;
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const state = params.get("state") ?? "";
  const codeChallenge = params.get("code_challenge") ?? "";
  const codeChallengeMethod = params.get("code_challenge_method") ?? "S256";

  return html(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>تسجيل الدخول - Sp</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #fafbff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    form { background: white; padding: 32px; border-radius: 16px; box-shadow: 0 20px 50px -12px rgba(0,0,0,0.12); width: 320px; }
    h1 { font-size: 18px; margin: 0 0 4px; color: #0f172a; }
    p { font-size: 13px; color: #64748b; margin: 0 0 20px; }
    input { width: 100%; padding: 10px 12px; margin-bottom: 12px; border: 1px solid #e2e8f0; border-radius: 10px; box-sizing: border-box; font-size: 14px; }
    button { width: 100%; padding: 12px; background: #6138f8; color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; font-size: 14px; }
    .err { color: #dc2626; font-size: 13px; margin-bottom: 10px; }
  </style>
</head>
<body>
  <form method="POST" action="/authorize">
    <h1>سجل دخولك لربط Claude بحساب Sp</h1>
    <p>بعد تسجيل الدخول، Claude رح يقدر ينشر نيابة عنك على الحسابات المربوطة عندك.</p>
    <input type="hidden" name="client_id" value="${clientId}" />
    <input type="hidden" name="redirect_uri" value="${redirectUri}" />
    <input type="hidden" name="state" value="${state}" />
    <input type="hidden" name="code_challenge" value="${codeChallenge}" />
    <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />
    <input type="email" name="email" placeholder="البريد الإلكتروني" required />
    <input type="password" name="password" placeholder="كلمة المرور" required />
    <button type="submit">تسجيل الدخول والموافقة</button>
  </form>
</body>
</html>`);
}

async function handleAuthorizePost(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const email = String(form.get("email") ?? "");
  const password = String(form.get("password") ?? "");
  const clientId = String(form.get("client_id") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const state = String(form.get("state") ?? "");
  const codeChallenge = String(form.get("code_challenge") ?? "");

  // تسجيل الدخول عبر Supabase Auth
  const authRes = await fetch(`${env.SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: env.SUPABASE_ANON_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!authRes.ok) {
    return html(`<p style="font-family:sans-serif;text-align:center;margin-top:60px;color:#dc2626">
      بيانات الدخول غلط. <a href="javascript:history.back()">ارجع وحاول مرة تانية</a></p>`, 401);
  }

  const authData: any = await authRes.json();
  const userId = authData.user?.id;
  if (!userId) return html("<p>خطأ غير متوقع</p>", 500);

  // أنشئ authorization code واحفظه
  const code = randomToken(24);
  await sbInsert(env, "sp_mcp_auth_codes", {
    code,
    user_id: userId,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);

  return Response.redirect(redirect.toString(), 302);
}

// ---------- OAuth: /token ----------

async function handleToken(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get("content-type") || "";
  let params: URLSearchParams;
  if (contentType.includes("application/json")) {
    const body: any = await request.json();
    params = new URLSearchParams(body);
  } else {
    params = new URLSearchParams(await request.text());
  }

  const grantType = params.get("grant_type");
  if (grantType !== "authorization_code") {
    return json({ error: "unsupported_grant_type" }, 400);
  }

  const code = params.get("code") ?? "";
  const codeVerifier = params.get("code_verifier") ?? "";

  const rows: any[] = await sbSelect(
    env,
    "sp_mcp_auth_codes",
    `code=eq.${encodeURIComponent(code)}&used=eq.false&select=*`
  );
  const authCode = rows[0];
  if (!authCode) return json({ error: "invalid_grant" }, 400);
  if (new Date(authCode.expires_at).getTime() < Date.now()) {
    return json({ error: "invalid_grant", error_description: "code expired" }, 400);
  }

  if (authCode.code_challenge) {
    const computed = await sha256Base64Url(codeVerifier);
    if (computed !== authCode.code_challenge) {
      return json({ error: "invalid_grant", error_description: "PKCE mismatch" }, 400);
    }
  }

  await sbUpdate(env, "sp_mcp_auth_codes", `code=eq.${encodeURIComponent(code)}`, { used: true });

  const accessToken = randomToken(32);
  const refreshToken = randomToken(32);
  await sbInsert(env, "sp_mcp_tokens", {
    user_id: authCode.user_id,
    access_token: accessToken,
    refresh_token: refreshToken,
    client_id: authCode.client_id,
    expires_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 90).toISOString(), // 90 يوم
  });

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 60 * 60 * 24 * 90,
    refresh_token: refreshToken,
  });
}

// ---------- OAuth: Dynamic Client Registration (اختياري لكن Claude بيتوقعه) ----------

async function handleRegister(request: Request): Promise<Response> {
  const body: any = await request.json().catch(() => ({}));
  return json({
    client_id: randomToken(16),
    client_name: body.client_name ?? "Claude",
    redirect_uris: body.redirect_uris ?? [],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
}

// ---------- Auth check helper for MCP calls ----------

async function getUserIdFromBearer(request: Request, env: Env): Promise<string | null> {
  const authHeader = request.headers.get("authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1];

  const rows: any[] = await sbSelect(
    env,
    "sp_mcp_tokens",
    `access_token=eq.${encodeURIComponent(token)}&revoked=eq.false&select=user_id,expires_at`
  );
  const row = rows[0];
  if (!row) return null;
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
  return row.user_id;
}

// ---------- Instagram publishing ----------

async function getInstagramAccounts(env: Env, userId: string) {
  return sbSelect(
    env,
    "sp_instagram_accounts",
    `user_id=eq.${encodeURIComponent(userId)}&select=id,ig_username,ig_user_id,access_token`
  );
}

async function publishInstagramPost(
  env: Env,
  userId: string,
  caption: string,
  imageUrl: string,
  accountId?: string
) {
  const accounts: any[] = await getInstagramAccounts(env, userId);
  if (accounts.length === 0) {
    throw new Error("ما في حساب إنستقرام مربوط بحسابك. روح اربط حساب من لوحة تحكم Sp أول.");
  }
  const account = accountId ? accounts.find((a) => a.id === accountId) : accounts[0];
  if (!account) throw new Error("الحساب المطلوب مش موجود");

  // 1. أنشئ media container
  const containerRes = await fetch(
    `https://graph.instagram.com/v21.0/${account.ig_user_id}/media`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        image_url: imageUrl,
        caption,
        access_token: account.access_token,
      }),
    }
  );
  const containerData: any = await containerRes.json();
  if (!containerRes.ok) {
    throw new Error(`فشل إنشاء المنشور: ${containerData?.error?.message ?? "خطأ غير معروف"}`);
  }

  // 2. انشر الـ container
  const publishRes = await fetch(
    `https://graph.instagram.com/v21.0/${account.ig_user_id}/media_publish`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        creation_id: containerData.id,
        access_token: account.access_token,
      }),
    }
  );
  const publishData: any = await publishRes.json();
  if (!publishRes.ok) {
    throw new Error(`فشل النشر: ${publishData?.error?.message ?? "خطأ غير معروف"}`);
  }

  return { post_id: publishData.id, account: account.ig_username };
}

// ---------- MCP JSON-RPC endpoint ----------

const TOOLS = [
  {
    name: "list_connected_accounts",
    description: "يرجع لائحة حسابات إنستقرام المربوطة بحساب المستخدم الحالي على منصة Sp",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "publish_instagram_post",
    description: "ينشر صورة مع كابشن على حساب إنستقرام المربوط بالمستخدم عبر منصة Sp",
    inputSchema: {
      type: "object",
      properties: {
        caption: { type: "string", description: "نص المنشور (الكابشن)" },
        image_url: { type: "string", description: "رابط مباشر للصورة (https) المطلوب نشرها" },
        account_id: { type: "string", description: "معرف الحساب إذا عند المستخدم أكثر من حساب مربوط (اختياري)" },
      },
      required: ["caption", "image_url"],
    },
  },
];

async function handleMcp(request: Request, env: Env): Promise<Response> {
  const userId = await getUserIdFromBearer(request, env);
  if (!userId) {
    return json(
      { jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null },
      401
    );
  }

  const body: any = await request.json();
  const { id, method, params } = body;

  try {
    if (method === "initialize") {
      return json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "sp-mcp", version: "0.1.0" },
        },
      });
    }

    if (method === "tools/list") {
      return json({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    }

    if (method === "tools/call") {
      const toolName = params?.name;
      const args = params?.arguments ?? {};

      if (toolName === "list_connected_accounts") {
        const accounts = await getInstagramAccounts(env, userId);
        const text = accounts.length
          ? accounts.map((a: any) => `- @${a.ig_username} (id: ${a.id})`).join("\n")
          : "ما في حسابات مربوطة حالياً.";
        return json({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text }] },
        });
      }

      if (toolName === "publish_instagram_post") {
        const result = await publishInstagramPost(
          env,
          userId,
          args.caption,
          args.image_url,
          args.account_id
        );
        return json({
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: `تم النشر بنجاح على @${result.account} ✅ (post_id: ${result.post_id})`,
              },
            ],
          },
        });
      }

      return json({
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` },
      });
    }

    return json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
  } catch (err: any) {
    return json({
      jsonrpc: "2.0",
      id,
      result: { content: [{ type: "text", text: `خطأ: ${err.message}` }], isError: true },
    });
  }
}

// ---------- Router ----------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // OAuth discovery metadata (MCP clients بتدور عليها تلقائياً)
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json({
        issuer: env.MCP_BASE_URL,
        authorization_endpoint: `${env.MCP_BASE_URL}/authorize`,
        token_endpoint: `${env.MCP_BASE_URL}/token`,
        registration_endpoint: `${env.MCP_BASE_URL}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      });
    }

    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json({
        resource: env.MCP_BASE_URL,
        authorization_servers: [env.MCP_BASE_URL],
      });
    }

    if (url.pathname === "/authorize" && request.method === "GET") {
      return handleAuthorizeGet(url);
    }
    if (url.pathname === "/authorize" && request.method === "POST") {
      return handleAuthorizePost(request, env);
    }
    if (url.pathname === "/token" && request.method === "POST") {
      return handleToken(request, env);
    }
    if (url.pathname === "/register" && request.method === "POST") {
      return handleRegister(request);
    }
    if (url.pathname === "/mcp" && request.method === "POST") {
      return handleMcp(request, env);
    }

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({ status: "ok", service: "sp-mcp" });
    }

    return json({ error: "not_found" }, 404);
  },
};
