export interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  IG_APP_ID: string;
  IG_APP_SECRET: string;
  MCP_BASE_URL: string;
  WEBHOOK_VERIFY_TOKEN: string;
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
  try {
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
    if (!userId) return html("<p>خطأ غير متوقع بتسجيل الدخول</p>", 500);

    if (!redirectUri) return html("<p>redirect_uri مفقود بالطلب</p>", 400);

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
  } catch (err: any) {
    return html(`<p style="font-family:sans-serif;text-align:center;margin-top:60px;color:#dc2626">صار خطأ: ${String(err?.message ?? err)}</p>`, 500);
  }
}

// ---------- OAuth: /token ----------

async function handleToken(request: Request, env: Env): Promise<Response> {
  try {
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
  } catch (err: any) {
    return json({ error: "server_error", error_description: String(err?.message ?? err) }, 500);
  }
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

// ---------- Instagram Webhooks: استقبال تعليقات جديدة والرد التلقائي ----------

function handleWebhookVerify(url: URL, env: Env): Response {
  const mode = url.searchParams.get("hub.mode");
  const token = url.searchParams.get("hub.verify_token");
  const challenge = url.searchParams.get("hub.challenge");

  if (mode === "subscribe" && token === env.WEBHOOK_VERIFY_TOKEN && challenge) {
    return new Response(challenge, { status: 200 });
  }
  return new Response("Forbidden", { status: 403 });
}

async function handleWebhookEvent(request: Request, env: Env): Promise<Response> {
  // نرجع 200 دايماً بسرعة لـ Meta (وإلا بتوقف الاشتراك)، والمعالجة تصير بالخلفية
  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response("ok", { status: 200 });
  }

  try {
    const entries = body?.entry ?? [];
    for (const entry of entries) {
      const igUserId = entry.id; // معرف حساب إنستقرام صاحب الحدث
      const changes = entry.changes ?? [];

      for (const change of changes) {
        if (change.field !== "comments") continue;
        const value = change.value ?? {};
        const commentId = value.id;
        const mediaId = value.media?.id;
        const commenterUsername = value.from?.username;
        if (!commentId || !mediaId) continue;

        // لا ترد على تعليقات الحساب نفسه (لتفادي حلقة لا نهائية)
        if (value.from?.id === igUserId) continue;

        // 1. دور على الحساب صاحب هاد الـ ig_user_id
        const accounts: any[] = await sbSelect(
          env,
          "sp_instagram_accounts",
          `ig_user_id=eq.${encodeURIComponent(igUserId)}&select=id,access_token`
        );
        const account = accounts[0];
        if (!account) continue;

        // 2. دور على قاعدة رد فعالة لنفس المنشور
        const rules: any[] = await sbSelect(
          env,
          "sp_auto_reply_rules",
          `instagram_account_id=eq.${encodeURIComponent(account.id)}&post_id=eq.${encodeURIComponent(mediaId)}&enabled=eq.true&select=id,reply_message`
        );
        const rule = rules[0];
        if (!rule) continue;

        // 3. تأكد ما انردينا على هاد التعليق قبل هيك (تفادي تكرار)
        try {
          await sbInsert(env, "sp_auto_reply_log", { rule_id: rule.id, comment_id: commentId });
        } catch {
          // إذا فشل الإدراج (unique constraint) يعني انردينا عليه قبل هيك، تجاهل
          continue;
        }

        // 4. ابعت الرد فعلياً
        await fetch(`https://graph.instagram.com/v21.0/${commentId}/replies`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: rule.reply_message, access_token: account.access_token }),
        });
      }
    }
  } catch (err) {
    console.error("webhook processing error", err);
  }

  return new Response("ok", { status: 200 });
}

async function getRecentPosts(env: Env, userId: string, accountId?: string) {
  const accounts: any[] = await getInstagramAccounts(env, userId);
  if (accounts.length === 0) throw new Error("ما في حساب إنستقرام مربوط بحسابك.");
  const account = accountId ? accounts.find((a) => a.id === accountId) : accounts[0];
  if (!account) throw new Error("الحساب المطلوب مش موجود");

  const res = await fetch(
    `https://graph.instagram.com/v21.0/${account.ig_user_id}/media?fields=id,caption,media_type,media_url,permalink,timestamp&limit=15&access_token=${account.access_token}`
  );
  const data: any = await res.json();
  if (!res.ok) throw new Error(`فشل جلب المنشورات: ${data?.error?.message ?? "خطأ غير معروف"}`);
  return { account, posts: data.data ?? [] };
}

async function getPostComments(env: Env, userId: string, postId: string, accountId?: string) {
  const accounts: any[] = await getInstagramAccounts(env, userId);
  const account = accountId ? accounts.find((a) => a.id === accountId) : accounts[0];
  if (!account) throw new Error("الحساب المطلوب مش موجود");

  const res = await fetch(
    `https://graph.instagram.com/v21.0/${postId}/comments?fields=id,text,username,timestamp&access_token=${account.access_token}`
  );
  const data: any = await res.json();
  if (!res.ok) throw new Error(`فشل جلب التعليقات: ${data?.error?.message ?? "خطأ غير معروف"}`);
  return { account, comments: data.data ?? [] };
}

async function replyToComment(
  env: Env,
  userId: string,
  commentId: string,
  message: string,
  accountId?: string
) {
  const accounts: any[] = await getInstagramAccounts(env, userId);
  const account = accountId ? accounts.find((a) => a.id === accountId) : accounts[0];
  if (!account) throw new Error("الحساب المطلوب مش موجود");

  const res = await fetch(`https://graph.instagram.com/v21.0/${commentId}/replies`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, access_token: account.access_token }),
  });
  const data: any = await res.json();
  if (!res.ok) throw new Error(`فشل إرسال الرد: ${data?.error?.message ?? "خطأ غير معروف"}`);
  return { reply_id: data.id, account: account.ig_username };
}

// ---------- Cron: فحص دوري للردود التلقائية (بديل عن webhooks بما إنه التطبيق لسا Development) ----------

async function pollAndAutoReply(env: Env) {
  const report: any = { rules_found: 0, details: [] };
  try {
    const rules: any[] = await sbSelect(
      env,
      "sp_auto_reply_rules",
      `enabled=eq.true&select=id,post_id,reply_message,instagram_account_id`
    );
    report.rules_found = rules.length;

    for (const rule of rules) {
      const detail: any = { rule_id: rule.id, post_id: rule.post_id };

      const accounts: any[] = await sbSelect(
        env,
        "sp_instagram_accounts",
        `id=eq.${encodeURIComponent(rule.instagram_account_id)}&select=access_token`
      );
      const account = accounts[0];
      if (!account) {
        detail.error = "account_not_found";
        report.details.push(detail);
        continue;
      }

      const res = await fetch(
        `https://graph.instagram.com/v21.0/${rule.post_id}/comments?fields=id,text&access_token=${account.access_token}`
      );
      const data: any = await res.json();
      detail.comments_api_status = res.status;
      if (!res.ok) {
        detail.error = data?.error?.message ?? JSON.stringify(data);
        report.details.push(detail);
        continue;
      }
      detail.comments_found = data.data?.length ?? 0;
      detail.replies = [];

      for (const comment of data.data ?? []) {
        let alreadyLogged = false;
        try {
          await sbInsert(env, "sp_auto_reply_log", { rule_id: rule.id, comment_id: comment.id });
        } catch {
          alreadyLogged = true;
        }

        if (alreadyLogged) {
          detail.replies.push({ comment_id: comment.id, status: "already_replied_before" });
          continue;
        }

        const replyRes = await fetch(`https://graph.instagram.com/v21.0/${comment.id}/replies`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: rule.reply_message, access_token: account.access_token }),
        });
        const replyData: any = await replyRes.json();
        detail.replies.push({
          comment_id: comment.id,
          status: replyRes.status,
          result: replyData,
        });
      }

      report.details.push(detail);
    }
  } catch (err: any) {
    report.fatal_error = String(err?.message ?? err);
  }
  return report;
}

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
  {
    name: "list_recent_posts",
    description: "يرجع آخر منشورات حساب إنستقرام المربوط (id, caption, رابط) عشان المستخدم يختار وحدة يشتغل عليها",
    inputSchema: {
      type: "object",
      properties: {
        account_id: { type: "string", description: "معرف الحساب (اختياري لو عنده حساب واحد بس)" },
      },
    },
  },
  {
    name: "get_post_comments",
    description: "يرجع تعليقات منشور معين (id, نص التعليق, اسم صاحبه) عشان تصير تكتب ردود عليها",
    inputSchema: {
      type: "object",
      properties: {
        post_id: { type: "string", description: "معرف المنشور (من list_recent_posts)" },
        account_id: { type: "string", description: "معرف الحساب (اختياري)" },
      },
      required: ["post_id"],
    },
  },
  {
    name: "reply_to_comment",
    description: "يرسل رد فعلي على تعليق محدد بمنشور إنستقرام (بعد ما تصيغ الرد بالمحادثة مع المستخدم)",
    inputSchema: {
      type: "object",
      properties: {
        comment_id: { type: "string", description: "معرف التعليق (من get_post_comments)" },
        message: { type: "string", description: "نص الرد المطلوب إرساله" },
        account_id: { type: "string", description: "معرف الحساب (اختياري)" },
      },
      required: ["comment_id", "message"],
    },
  },
];

async function handleMcp(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }, 400);
  }

  const { id, method, params } = body;

  try {
    // ملاحظة: تحقق الهوية داخل نفس try/catch عشان أي خطأ شبكة/قاعدة بيانات يرجع رد نضيف بدل ما يكسر الـ Worker
    const userId = await getUserIdFromBearer(request, env);
    if (!userId) {
      return json({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id }, 401);
    }

    if (method === "initialize") {
      return json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "sp-mcp", version: "0.2.0" },
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
        return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });
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
              { type: "text", text: `تم النشر بنجاح على @${result.account} ✅ (post_id: ${result.post_id})` },
            ],
          },
        });
      }

      if (toolName === "list_recent_posts") {
        const { account, posts } = await getRecentPosts(env, userId, args.account_id);
        const text = posts.length
          ? posts
              .map(
                (p: any) =>
                  `- id: ${p.id} | ${p.caption ? p.caption.slice(0, 60) : "(بدون كابشن)"} | ${p.permalink}`
              )
              .join("\n")
          : "ما في منشورات بهاد الحساب.";
        return json({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: `منشورات @${account.ig_username}:\n${text}` }] },
        });
      }

      if (toolName === "get_post_comments") {
        const { comments } = await getPostComments(env, userId, args.post_id, args.account_id);
        const text = comments.length
          ? comments.map((c: any) => `- id: ${c.id} | @${c.username}: ${c.text}`).join("\n")
          : "ما في تعليقات على هاد المنشور.";
        return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });
      }

      if (toolName === "reply_to_comment") {
        const result = await replyToComment(
          env,
          userId,
          args.comment_id,
          args.message,
          args.account_id
        );
        return json({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `تم إرسال الرد ✅ (reply_id: ${result.reply_id})` }],
          },
        });
      }

      return json({ jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
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
    try {
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

      if (url.pathname === "/webhooks/instagram" && request.method === "GET") {
        return handleWebhookVerify(url, env);
      }
      if (url.pathname === "/webhooks/instagram" && request.method === "POST") {
        return handleWebhookEvent(request, env);
      }

      // تشغيل يدوي للفحص الدوري (للاختبار الفوري بدون الانتظار للـ cron)
      if (url.pathname === "/run-poll" && request.method === "GET") {
        const report = await pollAndAutoReply(env);
        return json(report);
      }

      if (url.pathname === "/" || url.pathname === "/health") {
        return json({ status: "ok", service: "sp-mcp" });
      }

      return json({ error: "not_found" }, 404);
    } catch (err: any) {
      return json({ error: "internal_error", message: String(err?.message ?? err) }, 500);
    }
  },

  async scheduled(event: any, env: Env, ctx: any) {
    ctx.waitUntil(pollAndAutoReply(env));
  },
};
