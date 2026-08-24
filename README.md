# Sp MCP Server

MCP server يخلي Claude ينشر مباشرة على حسابات إنستقرام المربوطة بمستخدمي منصة Sp.

## النشر (Deploy)

```bash
cd mcp-server
npm install
npx wrangler login

# سرّيات لازم تضيفها قبل أول deploy:
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
# (خذها من Supabase Dashboard → Settings → API → service_role secret)

npx wrangler secret put IG_APP_ID
npx wrangler secret put IG_APP_SECRET
# (App ID/Secret تبع تطبيق randieb من Meta for Developers)

npm run deploy
```

بعد أول deploy، Cloudflare بيعطيك رابط بصيغة:
```
https://sp-mcp.<subdomain>.workers.dev
```

**لازم تحدّث** `MCP_BASE_URL` بملف `wrangler.toml` بنفس الرابط هاد، وتعيد `npm run deploy` مرة ثانية.

## الربط من Claude

المستخدم بيروح لإعدادات Claude → Connectors → Add custom connector، وبيحط:
```
https://sp-mcp.<subdomain>.workers.dev/mcp
```

Claude رح يكتشف تلقائياً endpoints الـ OAuth (`/.well-known/oauth-authorization-server`)، ويوديه لصفحة تسجيل الدخول (`/authorize`) لأول مرة بس.

## الأدوات المتاحة (Tools)

- `list_connected_accounts` — يرجع حسابات إنستقرام المربوطة
- `publish_instagram_post(caption, image_url, account_id?)` — ينشر صورة مع كابشن

## ملاحظات أمان

- توكنات إنستقرام مخزّنة بجدول `sp_instagram_accounts` بمشروع Supabase، محمية بـ Row Level Security
- الوصول من الـ Worker لقاعدة البيانات يتم عبر `service_role key` (يتجاوز RLS عمداً لأنه Server-side trusted)، فلازم هاد المفتاح يضل سري تماماً ومحفوظ كـ Wrangler secret فقط، ما ينحط بالكود أبداً
