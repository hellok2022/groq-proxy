// main.ts - Hardened Production Proxy for Codex + Grok
import { timingSafeEqual } from "https://deno.land/std@0.224.0/crypto/timing_safe_equal.ts";

// ==================== 配置区 ====================
const AUTH_TOKEN = Deno.env.get("AUTH_TOKEN");
if (!AUTH_TOKEN) throw new Error("FATAL: AUTH_TOKEN environment variable not set");

// 预编码 Token，避免每次请求重复编码
const AUTH_TOKEN_BYTES = new TextEncoder().encode(AUTH_TOKEN);

// ✅ 已添加 api.x.ai (Grok/xAI)
const ALLOWED_ORIGINS = new Set([
  "api.openai.com",
  "generativelanguage.googleapis.com",
  "api.anthropic.com",
  "api.x.ai",
]);

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB
const UPSTREAM_TIMEOUT_MS = 120_000; // Codex 任务可能较长，建议 120s
const ALLOWED_PROTOCOLS = new Set(["https:"]);

// 仅透传这些响应头给客户端
const SAFE_RESPONSE_HEADERS = new Set([
  "content-type", "content-length", "transfer-encoding",
  "cache-control", "etag", "last-modified",
  "x-request-id", "openai-version", "openai-organization",
  "anthropic-version", "x-ratelimit-limit", "x-ratelimit-remaining",
]);

// ==================== 工具函数 ====================
function jsonError(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * 验证 Token（支持 Header Bearer 和 URL Query 两种模式）
 * @param headerAuth - Authorization header 值
 * @param queryToken - URL ?token= 参数值
 */
function verifyAuth(headerAuth: string | null, queryToken: string | null): boolean {
  // 优先验证 Header (标准模式)
  if (headerAuth) {
    const prefix = "Bearer ";
    if (headerAuth.startsWith(prefix)) {
      const tokenBytes = new TextEncoder().encode(headerAuth.slice(prefix.length));
      if (tokenBytes.length === AUTH_TOKEN_BYTES.length &&
          timingSafeEqual(tokenBytes, AUTH_TOKEN_BYTES)) {
        return true;
      }
    }
  }

  // 回退验证 URL 参数 (Codex CLI 兼容模式)
  if (queryToken) {
    const queryBytes = new TextEncoder().encode(queryToken);
    if (queryBytes.length === AUTH_TOKEN_BYTES.length &&
        timingSafeEqual(queryBytes, AUTH_TOKEN_BYTES)) {
      return true;
    }
  }

  return false;
}

function validateTarget(urlStr: string): URL | null {
  try {
    const url = new URL(urlStr);
    if (!ALLOWED_PROTOCOLS.has(url.protocol)) return null;
    if (!ALLOWED_ORIGINS.has(url.hostname)) return null;
    return url;
  } catch {
    return null;
  }
}

/** 创建一个在达到 maxSize 时自动 abort 的 ReadableStream */
function sizeLimitedStream(
  stream: ReadableStream<Uint8Array>,
  maxSize: number,
  controller: AbortController,
): ReadableStream<Uint8Array> {
  let total = 0;
  return new ReadableStream({
    async start(c) {
      const reader = stream.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) { c.close(); break; }
          total += value.byteLength;
          if (total > maxSize) {
            controller.abort(new Error("Body size exceeded"));
            c.error(new Error("Body size exceeded"));
            return;
          }
          c.enqueue(value);
        }
      } catch (e) {
        c.error(e);
      } finally {
        reader.releaseLock();
      }
    },
  });
}

// ==================== 主服务 ====================
Deno.serve(async (req) => {
  const reqUrl = new URL(req.url);

  // 1. 双重鉴权（Header 优先，URL 参数回退）
  const headerAuth = req.headers.get("Authorization");
  const queryToken = reqUrl.searchParams.get("token");

  if (!verifyAuth(headerAuth, queryToken)) {
    // 故意延迟，防止侧信道攻击
    await new Promise((r) => setTimeout(r, 50));
    return jsonError("Unauthorized", 401);
  }

  // 2. 解析目标 URL
  let rawTarget: string | null = null;
  if (reqUrl.pathname.startsWith("/proxy/")) {
    rawTarget = decodeURIComponent(reqUrl.pathname.slice("/proxy/".length));
  } else {
    rawTarget = reqUrl.searchParams.get("url");
  }
  if (!rawTarget) return jsonError("Missing target URL", 400);

  // 3. 协议 + 域名双重校验
  const target = validateTarget(rawTarget);
  if (!target) return jsonError("Target blocked by policy", 403);

  // 4. 请求体大小预检
  const contentLength = Number(req.headers.get("Content-Length"));
  if (contentLength > MAX_BODY_SIZE) {
    return jsonError(`Body too large (max ${MAX_BODY_SIZE} bytes)`, 413);
  }

  // 5. 构建安全转发头
  const fwdHeaders = new Headers();
  const passthroughReqHeaders = [
    "content-type", "accept", "user-agent",
    "x-api-key", "authorization", "anthropic-version",
  ];
  for (const h of passthroughReqHeaders) {
    const v = req.headers.get(h);
    if (v) fwdHeaders.set(h, v);
  }

  // ⚠️ 关键：如果使用了 URL Token 鉴权，且客户端没有发 Authorization header
  // 我们需要确保不会把代理的 token 误当作上游 API key 转发
  // 但由于 verifyAuth 中 URL token 不走 header，这里天然安全

  // 6. 带超时 + 大小限制的转发
  const abortCtrl = new AbortController();
  const timer = setTimeout(() => abortCtrl.abort(new Error("Timeout")), UPSTREAM_TIMEOUT_MS);

  let body: ReadableStream<Uint8Array> | undefined;
  if (!["GET", "HEAD"].includes(req.method) && req.body) {
    body = sizeLimitedStream(req.body, MAX_BODY_SIZE, abortCtrl);
  }

  try {
    const upstream = await fetch(target.href, {
      method: req.method,
      headers: fwdHeaders,
      body,
      redirect: "manual",
      signal: abortCtrl.signal,
    });
    clearTimeout(timer);

    // 7. 过滤响应头
    const safeHeaders = new Headers();
    for (const [key, value] of upstream.headers) {
      if (SAFE_RESPONSE_HEADERS.has(key.toLowerCase())) {
        safeHeaders.set(key, value);
      }
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: safeHeaders,
    });
  } catch (e) {
    clearTimeout(timer);
    console.error(`[PROXY] ${req.method} ${target.href}:`, e.message);
    if (e.message === "Body size exceeded") return jsonError("Request body too large", 413);
    if (e.message === "Timeout") return jsonError("Upstream timeout", 504);
    return jsonError("Bad gateway", 502);
  }
});
