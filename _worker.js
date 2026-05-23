/**
 * Optimized Cloudflare Worker v2
 * 整合 edgetunnel + 优选IP订阅，修复 ReadableStream 锁定 & FAKE_WEB 问题
 *
 * 环境变量：
 *   UUID        主UUID，多个用英文逗号分隔（必填）
 *   TROJAN_PASS Trojan 密码（可选）
 *   PROXYIP     出口IP/域名，多行或逗号分隔（可选）
 *   SUB_TOKEN   订阅路径 token（默认 sub）
 *   FAKE_WEB    伪装反代 URL，必须是 https:// 开头的完整网址（可选）
 */

import { connect } from 'cloudflare:sockets';

// ── 默认值 ────────────────────────────────────────────────────────────────
const DEFAULT_UUID  = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const DEFAULT_TOKEN = 'sub';
const BUILTIN_PROXY = [
  'visa.cn:443',
  'time.cloudflare.com:443',
  'skk.moe:443',
  '104.16.0.0:443',
  '104.17.0.0:443',
  '172.64.0.0:443',
];

// ── 入口 ──────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const cfg  = buildConfig(env);
    const url  = new URL(request.url);
    const path = url.pathname.toLowerCase();

    // WebSocket → 代理核心
    if (request.headers.get('Upgrade') === 'websocket') {
      return handleWS(request, cfg);
    }

    // 订阅路由：支持路径 /sub 和查询参数 ?token=sub 两种方式（大小写均可）
    const tok     = cfg.subToken.toLowerCase();
    const qToken  = (url.searchParams.get('token') || '').toLowerCase();
    const qFmt    = (url.searchParams.get('fmt')   || '').toLowerCase();

    const isSubPath  = path === `/${tok}` || path === `/${tok}/clash` || path === `/${tok}/singbox`;
    const isSubQuery = qToken === tok;

    if (isSubPath || isSubQuery) {
      let fmt = 'base64';
      if (path.endsWith('/clash')   || qFmt === 'clash')   fmt = 'clash';
      if (path.endsWith('/singbox') || qFmt === 'singbox') fmt = 'singbox';
      return handleSub(request, cfg, fmt);
    }

    // 伪装首页 / 反向代理
    if (cfg.fakeWeb) {
      try {
        return await fetch(new URL(url.pathname + url.search, cfg.fakeWeb), {
          method: request.method,
          headers: request.headers,
          body: request.body,
        });
      } catch (_) { /* 反代失败则降级显示默认页 */ }
    }

    return new Response(fakePage(request.headers.get('host') || ''), {
      headers: { 'Content-Type': 'text/html;charset=utf-8' },
    });
  },
};

// ── 配置 ──────────────────────────────────────────────────────────────────
function buildConfig(env) {
  const uuids = (env.UUID || DEFAULT_UUID)
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

  // PROXYIP 支持逗号、空格、换行分隔
  const rawProxy = (env.PROXYIP || '').split(/[\n,\s]+/).map(s => s.trim()).filter(Boolean);
  const proxyList = rawProxy.length ? rawProxy : BUILTIN_PROXY;

  // FAKE_WEB 必须是 http(s):// 开头，否则忽略
  const fakeRaw = (env.FAKE_WEB || '').trim();
  const fakeWeb = /^https?:\/\//i.test(fakeRaw) ? fakeRaw.replace(/\/$/, '') : '';

  return {
    uuids,
    trojanPass: (env.TROJAN_PASS || '').trim(),
    proxyList,
    subToken  : (env.SUB_TOKEN || DEFAULT_TOKEN).trim(),
    fakeWeb,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket 处理
// ═══════════════════════════════════════════════════════════════════════════
async function handleWS(request, cfg) {
  const [client, server] = new WebSocketPair();
  server.accept();
  proxyWS(server, request.headers.get('sec-websocket-protocol') || '', cfg)
    .catch(() => { try { server.close(); } catch (_) {} });
  return new Response(null, { status: 101, webSocket: client });
}

async function proxyWS(ws, earlyData, cfg) {
  // ── 基于队列的数据读取器，避免 ReadableStream 锁定问题 ──
  const queue   = [];
  let   notify  = null;
  let   wsEnded = false;

  const push = chunk => {
    queue.push(chunk);
    if (notify) { notify(); notify = null; }
  };

  ws.addEventListener('message', ({ data }) =>
    push(data instanceof ArrayBuffer ? new Uint8Array(data) : new TextEncoder().encode(data))
  );
  ws.addEventListener('close', () => { wsEnded = true; if (notify) { notify(); notify = null; } });
  ws.addEventListener('error', () => { wsEnded = true; if (notify) { notify(); notify = null; } });

  if (earlyData) {
    try {
      const b = atob(earlyData.replace(/-/g, '+').replace(/_/g, '/'));
      push(new Uint8Array([...b].map(c => c.charCodeAt(0))));
    } catch (_) {}
  }

  const readChunk = async () => {
    if (queue.length)  return queue.shift();
    if (wsEnded)       return null;
    await new Promise(r => { notify = r; });
    return queue.length ? queue.shift() : null;
  };

  // ── 读取头部（至少 24 字节） ──
  let buf = new Uint8Array(0);
  while (buf.length < 24) {
    const chunk = await readChunk();
    if (!chunk) return;
    const tmp = new Uint8Array(buf.length + chunk.length);
    tmp.set(buf); tmp.set(chunk, buf.length);
    buf = tmp;
  }

  // ── 尝试 VLESS ──
  const vless = parseVless(buf, cfg.uuids);
  if (vless) {
    await relay(vless.host, vless.port, vless.rest, ws, readChunk, cfg, 'vless');
    return;
  }

  // ── 尝试 Trojan ──
  if (cfg.trojanPass) {
    const trojan = await parseTrojan(buf, cfg.trojanPass, readChunk);
    if (trojan) {
      await relay(trojan.host, trojan.port, trojan.rest, ws, readChunk, cfg, 'trojan');
      return;
    }
  }

  ws.close(1003, 'Unknown protocol');
}

// ── VLESS 解析（纯同步） ─────────────────────────────────────────────────
function parseVless(buf, uuids) {
  if (buf[0] !== 0) return null;
  const uuid = fmtUUID(buf.slice(1, 17));
  if (!uuids.includes(uuid)) return null;

  const addOn = buf[17];
  let   off   = 18 + addOn;
  const cmd   = buf[off++];
  const port  = (buf[off] << 8) | buf[off + 1]; off += 2;
  const atype = buf[off++];

  let host = '';
  if (atype === 1) {
    host = Array.from(buf.slice(off, off + 4)).join('.'); off += 4;
  } else if (atype === 2) {
    const dl = buf[off++];
    host = new TextDecoder().decode(buf.slice(off, off + dl)); off += dl;
  } else if (atype === 3) {
    const segs = [];
    for (let i = 0; i < 8; i++) segs.push(((buf[off + i*2] << 8) | buf[off + i*2 + 1]).toString(16));
    host = '[' + segs.join(':') + ']'; off += 16;
  } else return null;

  return { host, port, cmd, rest: buf.slice(off) };
}

// ── Trojan 解析 ───────────────────────────────────────────────────────────
async function parseTrojan(buf, pass, readChunk) {
  // Trojan 需要 56 字节 SHA-256 hex 前缀 + \r\n + cmd + atype + addr + port + \r\n
  while (buf.length < 62) {
    const chunk = await readChunk();
    if (!chunk) return null;
    const tmp = new Uint8Array(buf.length + chunk.length);
    tmp.set(buf); tmp.set(chunk, buf.length);
    buf = tmp;
  }
  const hash = await sha256hex56(pass);
  const incoming = new TextDecoder().decode(buf.slice(0, 56));
  if (incoming !== hash) return null;

  let off = 58; // skip hash + \r\n
  const atype = buf[off++];
  let host = '';
  if (atype === 1) {
    host = Array.from(buf.slice(off, off + 4)).join('.'); off += 4;
  } else if (atype === 3) {
    const dl = buf[off++];
    host = new TextDecoder().decode(buf.slice(off, off + dl)); off += dl;
  }
  const port = (buf[off] << 8) | buf[off + 1]; off += 4;
  return { host, port, rest: buf.slice(off) };
}

// ── TCP 中继 ──────────────────────────────────────────────────────────────
async function relay(host, port, firstData, ws, readChunk, cfg, proto) {
  const [ph, pp] = splitHostPort(cfg.proxyList[Math.floor(Math.random() * cfg.proxyList.length)], 443);

  let sock;
  try { sock = connect({ hostname: ph, port: pp }); }
  catch (e) { ws.close(); return; }

  const writer = sock.writable.getWriter();

  // VLESS 握手响应
  if (proto === 'vless') await writer.write(new Uint8Array([0, 0]));
  if (firstData?.length)  await writer.write(firstData);
  writer.releaseLock();

  // 远端 → WebSocket
  const tcpToWS = sock.readable.pipeTo(new WritableStream({
    write(chunk) { if (ws.readyState === 1) ws.send(chunk); },
    close()      { try { ws.close(); } catch (_) {} },
  })).catch(() => {});

  // WebSocket → 远端
  const wsToTCP = (async () => {
    const w = sock.writable.getWriter();
    while (true) {
      const chunk = await readChunk();
      if (!chunk) break;
      await w.write(chunk).catch(() => {});
    }
    w.releaseLock();
    sock.close?.();
  })();

  await Promise.allSettled([tcpToWS, wsToTCP]);
}

// ═══════════════════════════════════════════════════════════════════════════
// 订阅
// ═══════════════════════════════════════════════════════════════════════════
function handleSub(request, cfg, fmt) {
  const host  = request.headers.get('host') || '';
  const nodes = genNodes(host, cfg);

  if (fmt === 'clash')   return clashYaml(nodes, host);
  if (fmt === 'singbox') return singboxJson(nodes, host);

  const links = nodes.map(n => n.link).join('\n');
  return new Response(btoa(unescape(encodeURIComponent(links))), {
    headers: {
      'Content-Type': 'text/plain;charset=utf-8',
      'Subscription-Userinfo': 'upload=0;download=0;total=10995116277760;expire=9999999999',
      'Profile-Update-Interval': '6',
    },
  });
}

function genNodes(host, cfg) {
  const nodes = [];
  const proxies = cfg.proxyList.slice(0, 6);
  cfg.uuids.forEach(uuid => {
    proxies.forEach((proxy, i) => {
      const [ph] = splitHostPort(proxy, 443);
      const tag  = encodeURIComponent(`CF-${ph.split('.')[0]}-${i+1}`);
      nodes.push({
        uuid, host, proxyHost: ph,
        link: `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F#${tag}`,
        name: decodeURIComponent(tag), isTrojan: false,
      });
    });
    if (cfg.trojanPass) {
      proxies.forEach((proxy, i) => {
        const [ph] = splitHostPort(proxy, 443);
        const tag  = encodeURIComponent(`TJ-${ph.split('.')[0]}-${i+1}`);
        nodes.push({
          uuid: cfg.trojanPass, host, proxyHost: ph,
          link: `trojan://${cfg.trojanPass}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F#${tag}`,
          name: decodeURIComponent(tag), isTrojan: true,
        });
      });
    }
  });
  return nodes;
}

function clashYaml(nodes, host) {
  const proxies = nodes.map(n => ({
    name: n.name, type: n.isTrojan ? 'trojan' : 'vless',
    server: n.host, port: 443,
    ...(n.isTrojan ? { password: n.uuid } : { uuid: n.uuid }),
    tls: true, servername: n.host, network: 'ws',
    'ws-opts': { path: '/', headers: { Host: n.host } },
    'client-fingerprint': 'chrome',
  }));
  const names = proxies.map(p => `"${p.name}"`).join(', ');
  return new Response(`mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns:
  enable: true
  nameserver: [1.1.1.1, 8.8.8.8]
proxies:
${proxies.map(p => '  ' + JSON.stringify(p)).join('\n')}
proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies: [DIRECT, ${names}]
  - name: "♻️ 自动选择"
    type: url-test
    proxies: [${names}]
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
`, { headers: { 'Content-Type': 'text/yaml;charset=utf-8' } });
}

function singboxJson(nodes) {
  const outbounds = nodes.map(n => ({
    type: n.isTrojan ? 'trojan' : 'vless',
    tag : n.name, server: n.host, server_port: 443,
    ...(n.isTrojan ? { password: n.uuid } : { uuid: n.uuid }),
    tls: { enabled: true, server_name: n.host },
    transport: { type: 'ws', path: '/', headers: { Host: n.host } },
  }));
  const cfg = {
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: outbounds.map(o => o.tag) },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block',  tag: 'block'  },
    ],
    route: { rules: [{ geoip: ['cn'], outbound: 'direct' }], final: 'proxy' },
  };
  return new Response(JSON.stringify(cfg, null, 2), {
    headers: { 'Content-Type': 'application/json;charset=utf-8' },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// 伪装首页
// ═══════════════════════════════════════════════════════════════════════════
const fakePage = host => `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;padding:48px 64px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:480px}
h1{font-size:2rem;color:#1a1a2e;margin-bottom:8px}p{color:#666;font-size:.95rem;line-height:1.6}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
small{display:block;margin-top:24px;color:#aaa;font-size:.8rem}</style></head>
<body><div class="card"><h1>🌐 Service Running</h1>
<p><span class="dot"></span>This service is operating normally.</p>
<small>${host} · Powered by Cloudflare</small></div></body></html>`;

// ═══════════════════════════════════════════════════════════════════════════
// 工具
// ═══════════════════════════════════════════════════════════════════════════
const fmtUUID = b => {
  const h = [...b].map(x => x.toString(16).padStart(2,'0'));
  return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10).join('')}`;
};

const splitHostPort = (addr, def) => {
  const i = addr.lastIndexOf(':');
  if (i > 0) { const p = parseInt(addr.slice(i+1)); if (!isNaN(p)) return [addr.slice(0,i), p]; }
  return [addr, def];
};

const sha256hex56 = async str => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 56);
};
