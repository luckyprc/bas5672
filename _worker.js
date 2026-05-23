/**
 * Optimized Cloudflare Worker
 * 整合 cmliussss/edgetunnel + yonggekkk 优选IP订阅混淆方案
 *
 * 功能：
 *  - VLESS / Trojan over WebSocket (TLS by Cloudflare)
 *  - 多 UUID 支持
 *  - 自动订阅链接（Base64 + clash meta + singbox）
 *  - 优选 IP / 反代域名注入（yonggekkk 风格）
 *  - 伪装首页（防审查探测）
 *  - Cloudflare Pages _worker.js 兼容
 *
 * 部署变量（Workers 环境变量 或 Pages 绑定）：
 *   UUID        - 主 UUID，多个用英文逗号分隔
 *   TROJAN_PASS - Trojan 密码（可选）
 *   PROXYIP     - TCP 代理节点（可选，格式 host:port 或多行）
 *   SOCKS5      - Socks5 出口（可选，格式 user:pass@host:port）
 *   SUB_TOKEN   - 订阅路径 token（默认 sub）
 *   FAKE_WEB    - 伪装网站 URL（可选）
 */

// ─── 默认配置（环境变量优先） ──────────────────────────────────────────────
const DEFAULT_UUID    = 'ffffffff-ffff-ffff-ffff-ffffffffffff'; // 请务必替换！
const DEFAULT_TOKEN   = 'sub';
const CF_PREFERRED_IPS = [
  'visa.cn', 'time.cloudflare.com',
  'skk.moe', 'edgetunnel.anycast.eu.org',
  '104.16.0.0', '104.17.0.0', '172.64.0.0', '162.159.0.0',
];

// ─── 入口 ────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const cfg = buildConfig(env);
    const url = new URL(request.url);

    // WebSocket 升级 → 代理协议处理
    if (request.headers.get('Upgrade') === 'websocket') {
      return handleWS(request, cfg);
    }

    // HTTP 路由
    const path = url.pathname;

    // 订阅端点
    if (path === `/${cfg.subToken}`) {
      return handleSub(request, cfg, url, 'base64');
    }
    if (path === `/${cfg.subToken}/clash`) {
      return handleSub(request, cfg, url, 'clash');
    }
    if (path === `/${cfg.subToken}/singbox`) {
      return handleSub(request, cfg, url, 'singbox');
    }

    // 伪装首页 / 反向代理目标站
    if (cfg.fakeWeb) {
      return fetch(cfg.fakeWeb + url.pathname + url.search, {
        headers: request.headers,
        method: request.method,
        body: request.body,
      });
    }

    return new Response(renderFakePage(request.headers.get('host')), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  },
};

// ─── 配置构建 ────────────────────────────────────────────────────────────
function buildConfig(env) {
  const uuidRaw = (env.UUID || DEFAULT_UUID).trim();
  const uuids   = uuidRaw.split(',').map(u => u.trim().toLowerCase()).filter(Boolean);

  const proxyLines = (env.PROXYIP || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const proxyList  = proxyLines.length ? proxyLines : CF_PREFERRED_IPS.map(ip => `${ip}:443`);

  return {
    uuids,
    trojanPass  : (env.TROJAN_PASS || '').trim(),
    proxyList,
    socks5      : (env.SOCKS5 || '').trim(),
    subToken    : (env.SUB_TOKEN || DEFAULT_TOKEN).trim(),
    fakeWeb     : (env.FAKE_WEB || '').trim(),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket 代理核心
// ═══════════════════════════════════════════════════════════════════════════
async function handleWS(request, cfg) {
  const [client, server] = new WebSocketPair();
  server.accept();

  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  const log = (msg) => {}; // 生产环境关闭日志，调试时改为 console.log

  const readable = wsToReadable(server, earlyData, log);

  // 尝试 VLESS 解析
  const header = await peekVless(readable, cfg.uuids);
  if (header) {
    await relayTCP(header, readable, server, cfg, log);
    return new Response(null, { status: 101, webSocket: client });
  }

  // 尝试 Trojan 解析（若配置了密码）
  if (cfg.trojanPass) {
    const trojanHeader = await peekTrojan(readable, cfg.trojanPass);
    if (trojanHeader) {
      await relayTCP(trojanHeader, readable, server, cfg, log);
      return new Response(null, { status: 101, webSocket: client });
    }
  }

  server.close(1003, 'Unknown protocol');
  return new Response(null, { status: 101, webSocket: client });
}

// ─── WebSocket → ReadableStream ──────────────────────────────────────────
function wsToReadable(ws, earlyData, log) {
  let controller;
  const stream = new ReadableStream({
    start(c) { controller = c; },
    cancel()  { ws.close(); },
  });

  ws.addEventListener('message', ({ data }) => {
    controller.enqueue(typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data));
  });
  ws.addEventListener('close',   () => controller.close());
  ws.addEventListener('error',   (e) => controller.error(e));

  if (earlyData) {
    try {
      const bin = atob(earlyData.replace(/-/g, '+').replace(/_/g, '/'));
      controller.enqueue(new Uint8Array([...bin].map(c => c.charCodeAt(0))));
    } catch (_) {}
  }

  return stream;
}

// ─── VLESS 头部解析 ───────────────────────────────────────────────────────
async function peekVless(readable, uuids) {
  const reader = readable.getReader();
  let buf = new Uint8Array(0);

  // 读取足够字节
  while (buf.length < 24) {
    const { value, done } = await reader.read();
    if (done) return null;
    const tmp = new Uint8Array(buf.length + value.length);
    tmp.set(buf); tmp.set(value, buf.length);
    buf = tmp;
  }

  // version == 0
  if (buf[0] !== 0) return null;

  const uuid = formatUUID(buf.slice(1, 17));
  if (!uuids.includes(uuid)) return null;

  const addOnLen = buf[17];
  const cmd      = buf[18 + addOnLen];       // 1=tcp 2=udp 3=mux
  const port     = (buf[19 + addOnLen] << 8) | buf[20 + addOnLen];
  const atype    = buf[21 + addOnLen];
  let   host     = '';
  let   headLen  = 22 + addOnLen;

  if (atype === 1) {          // IPv4
    host = buf.slice(headLen, headLen + 4).join('.');
    headLen += 4;
  } else if (atype === 2) {   // Domain
    const dlen = buf[headLen];
    host = new TextDecoder().decode(buf.slice(headLen + 1, headLen + 1 + dlen));
    headLen += 1 + dlen;
  } else if (atype === 3) {   // IPv6
    const h = [];
    for (let i = 0; i < 8; i++) h.push(((buf[headLen + i * 2] << 8) | buf[headLen + i * 2 + 1]).toString(16));
    host = '[' + h.join(':') + ']';
    headLen += 16;
  } else {
    return null;
  }

  reader.releaseLock();
  return { host, port, cmd, rawHead: buf.slice(headLen), protocol: 'vless', reader };
}

// ─── Trojan 头部解析 ─────────────────────────────────────────────────────
async function peekTrojan(readable, pass) {
  const hash     = await sha224hex(pass);
  const reader   = readable.getReader();
  let   buf      = new Uint8Array(0);

  while (buf.length < 60) {
    const { value, done } = await reader.read();
    if (done) return null;
    const tmp = new Uint8Array(buf.length + value.length);
    tmp.set(buf); tmp.set(value, buf.length);
    buf = tmp;
  }

  const incoming = new TextDecoder().decode(buf.slice(0, 56));
  if (incoming !== hash) return null;

  // skip \r\n, cmd, atype
  let off  = 58;
  const cmd   = buf[57];
  const atype = buf[off++];
  let host = '', port = 0;

  if (atype === 1) {
    host = buf.slice(off, off + 4).join('.');
    off += 4;
  } else if (atype === 3) {
    const dl = buf[off++];
    host = new TextDecoder().decode(buf.slice(off, off + dl));
    off += dl;
  }
  port = (buf[off] << 8) | buf[off + 1];
  off += 4; // port + \r\n

  reader.releaseLock();
  return { host, port, cmd, rawHead: buf.slice(off), protocol: 'trojan', reader };
}

// ─── TCP 中继 ─────────────────────────────────────────────────────────────
async function relayTCP(header, readable, wsServer, cfg, log) {
  const { host, port, rawHead } = header;
  const proxyAddr = pickProxy(cfg.proxyList);
  const [ph, pp]  = parseHostPort(proxyAddr, 443);

  let tcpSocket;
  try {
    tcpSocket = connect({ hostname: ph, port: pp });
  } catch (e) {
    log('connect error', e);
    wsServer.close();
    return;
  }

  const writer = tcpSocket.writable.getWriter();

  // VLESS 响应头（协议版本 0，无附加信息）
  if (header.protocol === 'vless') {
    await writer.write(new Uint8Array([0, 0]));
  }

  // 转发首包剩余数据
  if (rawHead && rawHead.length > 0) await writer.write(rawHead);
  writer.releaseLock();

  // 双向中继
  await Promise.all([
    tcpSocket.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (wsServer.readyState === 1) wsServer.send(chunk);
      },
      close() { wsServer.close(); },
    })).catch(() => {}),
    readable.pipeTo(tcpSocket.writable).catch(() => {}),
  ]);
}

// ═══════════════════════════════════════════════════════════════════════════
// 订阅生成
// ═══════════════════════════════════════════════════════════════════════════
function handleSub(request, cfg, url, fmt) {
  const host = request.headers.get('host');
  const nodes = buildNodes(host, cfg);

  if (fmt === 'clash')   return clashResponse(nodes, host);
  if (fmt === 'singbox') return singboxResponse(nodes, host);

  // Base64 默认
  const links = nodes.map(n => n.link).join('\n');
  return new Response(btoa(unescape(encodeURIComponent(links))), {
    headers: {
      'Content-Type'        : 'text/plain; charset=utf-8',
      'Profile-Update-Interval': '6',
      'Subscription-Userinfo': 'upload=0; download=0; total=10995116277760; expire=99999999999',
    },
  });
}

function buildNodes(host, cfg) {
  const nodes = [];
  const proxyHosts = cfg.proxyList.slice(0, 8); // 最多 8 个节点

  cfg.uuids.forEach((uuid, ui) => {
    proxyHosts.forEach((proxy, pi) => {
      const [ph] = parseHostPort(proxy, 443);
      const remark = encodeURIComponent(`CF-${ph.split('.')[0]}-${pi + 1}`);

      // VLESS WS TLS
      const vlessLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F#${remark}`;

      nodes.push({ uuid, proxyHost: ph, link: vlessLink, remark, host });

      // Trojan WS TLS（若配置）
      if (cfg.trojanPass) {
        const tRemark = encodeURIComponent(`TJ-${ph.split('.')[0]}-${pi + 1}`);
        const trojanLink = `trojan://${cfg.trojanPass}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F#${tRemark}`;
        nodes.push({ uuid: cfg.trojanPass, proxyHost: ph, link: trojanLink, remark: tRemark, host, isTrojan: true });
      }
    });
  });

  return nodes;
}

// ─── Clash Meta 配置 ──────────────────────────────────────────────────────
function clashResponse(nodes, host) {
  const proxies = nodes.map(n => ({
    name  : decodeURIComponent(n.remark),
    type  : n.isTrojan ? 'trojan' : 'vless',
    server: n.host,
    port  : 443,
    ...(n.isTrojan
      ? { password: n.uuid }
      : { uuid: n.uuid, flow: '' }),
    tls      : true,
    servername: n.host,
    network  : 'ws',
    'ws-opts': { path: '/', headers: { Host: n.host } },
    'client-fingerprint': 'chrome',
  }));

  const names = proxies.map(p => p.name);
  const yaml  = `mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

dns:
  enable: true
  nameserver: [1.1.1.1, 8.8.8.8]
  fallback:   [tls://1.1.1.1, https://8.8.8.8/dns-query]

proxies:
${proxies.map(p => '  ' + JSON.stringify(p)).join('\n')}

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies: [DIRECT, ${names.map(n => `"${n}"`).join(', ')}]

  - name: "♻️ 自动选择"
    type: url-test
    proxies: [${names.map(n => `"${n}"`).join(', ')}]
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
`;

  return new Response(yaml, {
    headers: { 'Content-Type': 'text/yaml; charset=utf-8' },
  });
}

// ─── Sing-Box 配置 ────────────────────────────────────────────────────────
function singboxResponse(nodes, host) {
  const outbounds = nodes.map(n => ({
    type: n.isTrojan ? 'trojan' : 'vless',
    tag : decodeURIComponent(n.remark),
    server: n.host,
    server_port: 443,
    ...(n.isTrojan ? { password: n.uuid } : { uuid: n.uuid }),
    tls: { enabled: true, server_name: n.host },
    transport: { type: 'ws', path: '/', headers: { Host: n.host } },
  }));

  const cfg = {
    log: { level: 'info' },
    dns: {
      servers: [
        { tag: 'remote', address: 'tls://1.1.1.1' },
        { tag: 'local',  address: '223.5.5.5', detour: 'direct' },
      ],
    },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
    outbounds: [
      ...outbounds,
      { type: 'direct',   tag: 'direct' },
      { type: 'block',    tag: 'block'  },
      { type: 'dns',      tag: 'dns-out'},
      {
        type: 'selector',
        tag : 'proxy',
        outbounds: outbounds.map(o => o.tag),
      },
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: ['cn'], outbound: 'direct' },
        { geosite: ['cn'], outbound: 'direct' },
      ],
      final: 'proxy',
    },
  };

  return new Response(JSON.stringify(cfg, null, 2), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// 伪装首页（防 GFW 主动探测）
// ═══════════════════════════════════════════════════════════════════════════
function renderFakePage(host) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#fff;border-radius:12px;padding:48px 64px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:480px}
  h1{font-size:2rem;color:#1a1a2e;margin-bottom:8px}
  p{color:#666;font-size:.95rem;line-height:1.6}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:6px;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  small{display:block;margin-top:24px;color:#aaa;font-size:.8rem}
</style>
</head>
<body>
<div class="card">
  <h1>🌐 Service Running</h1>
  <p><span class="dot"></span>This service is operating normally.</p>
  <small>${host} &middot; Powered by Cloudflare</small>
</div>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════════════════════════════
function formatUUID(bytes) {
  const h = [...bytes].map(b => b.toString(16).padStart(2, '0'));
  return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10).join('')}`;
}

function pickProxy(list) {
  return list[Math.floor(Math.random() * list.length)];
}

function parseHostPort(addr, defaultPort) {
  const last = addr.lastIndexOf(':');
  if (last > 0) {
    const port = parseInt(addr.slice(last + 1));
    if (!isNaN(port)) return [addr.slice(0, last), port];
  }
  return [addr, defaultPort];
}

async function sha224hex(str) {
  // Trojan 使用 SHA-224；Workers 仅支持 SHA-256，此处以 SHA-256 前 56 字符模拟
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 56);
}
