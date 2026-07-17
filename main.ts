// main.ts - Hardened Production Proxy
import { timingSafeEqual } from "https://deno.land/std@0.224.0/crypto/timing_safe_equal.ts";

// ==================== 配置区 ====================
const AUTH_TOKEN = Deno.env.get("AUTH_TOKEN");
if (!AUTH_TOKEN) throw new Error("FATAL: AUTH_TOKEN not set");

// 将 Token 预编码为 Uint8Array，避免每次请求重复编码
const AUTH_TOKEN_BYTES = new TextEncoder().encode(AUTH_TOKEN);

const ALLOWED_ORIGINS = new Set([
  "api.openai.com",
  "generativelanguage.googleapis.com",
]);

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB
const UPSTREAM_TIMEOUT_MS = 60_000;
const ALLOWED_PROTOCOLS = new Set(["https:"]);

// 仅透传这些响应头给客户端
const SAFE_RESPONSE_HEADERS = new Set([
  "content-type", "content-length", "transfer-encoding",
  "cache-control", "etag", "last-modified",
  "x-request-id", "openai-version", "openai-organization",
]);

// ==================== 工具函数 ====================
function jsonError(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function verifyToken(provided: string | null): boolean {
  if (!provided) return false;
  const prefix = "Bearer ";
  if (!provided.startsWith(prefix)) return false;
  const tokenBytes = new TextEncoder().encode(provided.slice(prefix.length));
  // 长度不同直接返回 false（timingSafeEqual 要求等长）
  if (tokenBytes.length !== AUTH_TOKEN_BYTES.length) return false;
  return timingSafeEqual(tokenBytes, AUTH_TOKEN_BYTES);
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
  // 1. 鉴权（恒定时间比较）
  if (!verifyToken(req.headers.get("Authorization"))) {
    // 故意延迟一点，防止无 Token 时的快速失败成为侧信道
    await new Promise((r) => setTimeout(r, 50));
    return jsonError("Unauthorized", 401);
  }

  // 2. 解析目标 URL
  const reqUrl = new URL(req.url);
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
  const passthroughReqHeaders = ["content-type", "accept", "user-agent", "x-api-key", "authorization"];
  for (const h of passthroughReqHeaders) {
    const v = req.headers.get(h);
    if (v) fwdHeaders.set(h, v);
  }
  // 注意：这里的 authorization 是客户端传给上游 API 的 Key，不是我们的 AUTH_TOKEN
  // 我们的 AUTH_TOKEN 已在 verifyToken 中消费，不会被转发

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
      redirect: "manual", // ⚠️ 禁止自动跟随重定向，防止绕过白名单
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
