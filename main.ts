// ═══════════════════════════════════════════════════════
//  NEXUS VPN  •  Deno Deploy  v5.0 (DNS FIX)
//  VLESS WS Proxy + Telegram Bot + Subscription
//  + DNS-over-HTTPS для полноценной работы браузера
// ═══════════════════════════════════════════════════════

const BRAND      = "Nexus VPN";
const EMOJI_LOGO = "🛡";
const VLESS_PATH = "/vless";

const BOT_TOKEN  = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const PROXY_UUID = Deno.env.get("PROXY_UUID") ?? "";
const ADMIN_TGID = Deno.env.get("ADMIN_TGID") ?? "";

const REDIS_URL   = Deno.env.get("UPSTASH_REDIS_REST_URL") ?? "";
const REDIS_TOKEN = Deno.env.get("UPSTASH_REDIS_REST_TOKEN") ?? "";

// DNS-over-HTTPS провайдер
const DOH_URL = "https://cloudflare-dns.com/dns-query";

// ═════════════════════════════════════════════════════
//  UPSTASH REDIS
// ═════════════════════════════════════════════════════

async function redis(command: string[]): Promise<unknown> {
  const resp = await fetch(REDIS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });
  const data = await resp.json();
  return data.result;
}

async function kvGet(key: string): Promise<string | null> {
  return (await redis(["GET", key])) as string | null;
}

async function kvSet(key: string, value: string): Promise<void> {
  await redis(["SET", key, value]);
}

async function kvDel(key: string): Promise<void> {
  await redis(["DEL", key]);
}

async function kvKeys(prefix: string): Promise<string[]> {
  return ((await redis(["KEYS", `${prefix}*`])) as string[]) || [];
}

// ═════════════════════════════════════════════════════
//  УТИЛИТЫ
// ═════════════════════════════════════════════════════

function generateUUID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
    hex.slice(16, 20), hex.slice(20),
  ].join("-");
}

function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToUUID(bytes: Uint8Array): string {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
    hex.slice(16, 20), hex.slice(20),
  ].join("-");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function buildVlessUri(uuid: string, host: string, remark = BRAND): string {
  const params = [
    "encryption=none",
    "security=tls",
    `sni=${host}`,
    "fp=randomized",
    "type=ws",
    `host=${host}`,
    `path=${encodeURIComponent(VLESS_PATH)}`,
  ].join("&");
  return `vless://${uuid}@${host}:443?${params}#${encodeURIComponent(remark)}`;
}

function buildSubscription(links: string[]): string {
  return btoa(links.join("\n"));
}

// ═════════════════════════════════════════════════════
//  VLESS PROTOCOL PARSER
// ═════════════════════════════════════════════════════

interface VlessHeader {
  version: number;
  uuid: Uint8Array;
  command: number; // 1=TCP, 2=UDP
  port: number;
  address: string;
  payload: Uint8Array;
}

function parseVlessHeader(buffer: ArrayBuffer): VlessHeader | null {
  const data = new Uint8Array(buffer);
  if (data.length < 24) return null;

  const version  = data[0];
  const uuid     = data.slice(1, 17);
  const addonLen = data[17];
  let offset     = 18 + addonLen;

  if (offset >= data.length) return null;

  const command = data[offset++];
  const port    = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  const addrType = data[offset++];
  let address = "";

  if (addrType === 1) {
    if (offset + 4 > data.length) return null;
    address = `${data[offset]}.${data[offset+1]}.${data[offset+2]}.${data[offset+3]}`;
    offset += 4;
  } else if (addrType === 2) {
    const domainLen = data[offset++];
    if (offset + domainLen > data.length) return null;
    address = new TextDecoder().decode(data.slice(offset, offset + domainLen));
    offset += domainLen;
  } else if (addrType === 3) {
    if (offset + 16 > data.length) return null;
    const parts: string[] = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((data[offset + i*2] << 8) | data[offset + i*2 + 1]).toString(16));
    }
    address = parts.join(":");
    offset += 16;
  } else {
    return null;
  }

  return { version, uuid, command, port, address, payload: data.slice(offset) };
}

// ═════════════════════════════════════════════════════
//  UUID АВТОРИЗАЦИЯ
// ═════════════════════════════════════════════════════

async function isUUIDAllowed(clientUUID: Uint8Array): Promise<boolean> {
  const masterBytes = uuidToBytes(PROXY_UUID);
  if (bytesEqual(clientUUID, masterBytes)) return true;

  const uuidStr = bytesToUUID(clientUUID);
  const result = await kvGet(`uuid:${uuidStr}`);
  return result !== null;
}

// ═════════════════════════════════════════════════════
//  DNS-over-HTTPS HANDLER (ключевой фикс!)
// ═════════════════════════════════════════════════════

async function handleDnsQuery(dnsPayload: Uint8Array): Promise<Uint8Array> {
  try {
    const resp = await fetch(DOH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/dns-message",
        "Accept":       "application/dns-message",
      },
      body: dnsPayload,
    });

    if (!resp.ok) {
      throw new Error(`DoH response: ${resp.status}`);
    }

    const answer = new Uint8Array(await resp.arrayBuffer());
    return answer;
  } catch (err) {
    console.error("DoH error:", err);
    // Возвращаем SERVFAIL
    const fail = new Uint8Array(dnsPayload.length);
    fail.set(dnsPayload);
    if (fail.length > 3) {
      fail[2] = 0x81; // QR=1, RD=1
      fail[3] = 0x82; // RA=1, RCODE=SERVFAIL
    }
    return fail;
  }
}

/** Оборачиваем DNS-ответ для отправки через VLESS UDP */
function packUdpResponse(data: Uint8Array): Uint8Array {
  // VLESS UDP формат: [len_hi, len_lo, ...data]
  const packed = new Uint8Array(2 + data.length);
  packed[0] = (data.length >> 8) & 0xff;
  packed[1] = data.length & 0xff;
  packed.set(data, 2);
  return packed;
}

/** Извлекаем DNS-запросы из VLESS UDP payload */
function unpackUdpPayload(payload: Uint8Array): Uint8Array[] {
  const packets: Uint8Array[] = [];
  let offset = 0;

  while (offset + 2 <= payload.length) {
    const len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;
    if (offset + len > payload.length) break;
    packets.push(payload.slice(offset, offset + len));
    offset += len;
  }

  // Если не удалось распарсить как length-prefixed — весь payload это один пакет
  if (packets.length === 0 && payload.length > 0) {
    packets.push(payload);
  }

  return packets;
}

// ═════════════════════════════════════════════════════
//  VLESS WebSocket PROXY (TCP + UDP/DNS)
// ═════════════════════════════════════════════════════

function handleVlessWs(request: Request): Response {
  const { socket: ws, response } = Deno.upgradeWebSocket(request);

  let headerParsed = false;
  let tcpConn: Deno.TcpConn | null = null;
  let isUdpMode = false;

  ws.binaryType = "arraybuffer";

  ws.onmessage = async (event: MessageEvent) => {
    try {
      let rawData: ArrayBuffer;
      if (event.data instanceof ArrayBuffer) {
        rawData = event.data;
      } else if (event.data instanceof Blob) {
        rawData = await event.data.arrayBuffer();
      } else {
        return;
      }

      if (!headerParsed) {
        const parsed = parseVlessHeader(rawData);
        if (!parsed) {
          ws.close(1002, "Invalid VLESS header");
          return;
        }

        // ── Авторизация ──
        const allowed = await isUUIDAllowed(parsed.uuid);
        if (!allowed) {
          const resp = new Uint8Array([parsed.version, 0]);
          ws.send(resp.buffer);
          setTimeout(() => { try { ws.close(1002, "Unauthorized"); } catch {} }, 100);
          return;
        }

        headerParsed = true;

        // ═══════════════════════════════════════
        //  UDP MODE (DNS)
        // ═══════════════════════════════════════
        if (parsed.command === 2) {
          isUdpMode = true;

          // Отправляем VLESS response header
          const responseHeader = new Uint8Array([parsed.version, 0]);
          ws.send(responseHeader.buffer);

          // Обрабатываем DNS-запросы из первого payload
          if (parsed.payload.length > 0) {
            const dnsQueries = unpackUdpPayload(parsed.payload);
            for (const query of dnsQueries) {
              const answer = await handleDnsQuery(query);
              const packed = packUdpResponse(answer);
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(packed.buffer);
              }
            }
          }
          return;
        }

        // ═══════════════════════════════════════
        //  TCP MODE (обычный трафик)
        // ═══════════════════════════════════════
        if (parsed.command === 1) {
          try {
            tcpConn = await Deno.connect({
              hostname: parsed.address,
              port: parsed.port,
            });

            const responseHeader = new Uint8Array([parsed.version, 0]);
            ws.send(responseHeader.buffer);

            if (parsed.payload.length > 0) {
              await tcpConn.write(parsed.payload);
            }

            pipeTcpToWs(tcpConn, ws);
          } catch (err) {
            console.error("TCP connect failed:", parsed.address, parsed.port, err);
            try { ws.close(1002, "TCP connect failed"); } catch {}
          }
          return;
        }

        // Неизвестная команда
        ws.close(1002, "Unsupported command");
        return;

      } else {
        // ═══════════════════════════════════════
        //  Последующие пакеты
        // ═══════════════════════════════════════

        if (isUdpMode) {
          // UDP: ещё DNS-запросы
          const data = new Uint8Array(rawData);
          const dnsQueries = unpackUdpPayload(data);
          for (const query of dnsQueries) {
            const answer = await handleDnsQuery(query);
            const packed = packUdpResponse(answer);
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(packed.buffer);
            }
          }
        } else {
          // TCP: пересылаем в соединение
          if (tcpConn) {
            try {
              await tcpConn.write(new Uint8Array(rawData));
            } catch {
              try { ws.close(); } catch {}
            }
          }
        }
      }
    } catch (e) {
      console.error("WS error:", e);
      try { ws.close(); } catch {}
    }
  };

  ws.onclose = () => { try { tcpConn?.close(); } catch {} };
  ws.onerror = () => { try { tcpConn?.close(); } catch {} };

  return response;
}

async function pipeTcpToWs(tcp: Deno.TcpConn, ws: WebSocket): Promise<void> {
  const buffer = new Uint8Array(32768);
  try {
    while (true) {
      const n = await tcp.read(buffer);
      if (n === null) break;
      if (ws.readyState !== WebSocket.OPEN) break;
      ws.send(buffer.slice(0, n));
    }
  } catch {} finally {
    try { ws.close(); } catch {}
  }
}

// ═════════════════════════════════════════════════════
//  TELEGRAM API
// ═════════════════════════════════════════════════════

async function tgApi(method: string, body: Record<string, unknown>) {
  const resp = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return resp.json();
}

function sendMessage(chatId: number | string, text: string, extra: Record<string, unknown> = {}) {
  return tgApi("sendMessage", { chat_id: chatId, text, parse_mode: "HTML", ...extra });
}

// ═════════════════════════════════════════════════════
//  BOT COMMANDS
// ═════════════════════════════════════════════════════

async function cmdStart(chatId: number, from: Record<string, string>) {
  const name = from.first_name || "друг";
  await sendMessage(chatId,
`${EMOJI_LOGO} <b>Добро пожаловать в ${BRAND}!</b>

Привет, <b>${name}</b>! 👋

Получи <b>бесплатный VPN-ключ</b> для <b>V2RayTUN</b>.

🔹 Безлимитный трафик
🔹 Без логов и рекламы
🔹 Высокая скорость
🔹 Полная работа браузера`, {
    reply_markup: {
      inline_keyboard: [
        [{ text: "🔑 Получить ключ", callback_data: "get_key" }],
        [{ text: "📋 Мой ключ", callback_data: "my_key" }, { text: "❓ Помощь", callback_data: "help" }],
      ],
    },
  });
}

async function cmdGetKey(chatId: number, userId: string, host: string) {
  const existing = await kvGet(`user:${userId}`);

  if (existing) {
    const data = JSON.parse(existing);
    const vlessUri = buildVlessUri(data.uuid, host, `${BRAND} • ${data.name}`);
    await sendMessage(chatId,
`⚠️ <b>У тебя уже есть ключ!</b>

<code>${vlessUri}</code>

🔗 Подписка: <code>https://${host}/sub/${userId}</code>

Хочешь новый? Сначала удали: /delete`);
    return;
  }

  const uuid = generateUUID();
  const userData = {
    uuid, userId,
    name: `User-${userId.slice(-4)}`,
    createdAt: new Date().toISOString(),
    active: true,
  };

  await kvSet(`user:${userId}`, JSON.stringify(userData));
  await kvSet(`uuid:${uuid}`, userId);

  const vlessUri = buildVlessUri(uuid, host, `${BRAND} • ${userData.name}`);

  await sendMessage(chatId,
`${EMOJI_LOGO} <b>Твой ключ ${BRAND} готов!</b>

<b>🔑 VLESS-ключ:</b>
<code>${vlessUri}</code>

<b>🔗 Подписка:</b>
<code>https://${host}/sub/${userId}</code>

━━━━━━━━━━━━━━━━
<b>📲 Как подключиться:</b>

1️⃣ Скачай <b>V2RayTUN</b>
2️⃣ Скопируй ключ (нажми на него)
3️⃣ V2RayTUN → <b>➕ → Импорт из буфера</b>
4️⃣ Нажми <b>▶️ Подключиться</b>
━━━━━━━━━━━━━━━━`, {
    reply_markup: {
      inline_keyboard: [
        [{ text: "📋 Мой ключ", callback_data: "my_key" }],
        [{ text: "🗑 Удалить и пересоздать", callback_data: "delete_key" }],
      ],
    },
  });
}

async function cmdMyKey(chatId: number, userId: string, host: string) {
  const existing = await kvGet(`user:${userId}`);
  if (!existing) {
    await sendMessage(chatId, "❌ Ключа нет.\nНажми /getkey чтобы получить.");
    return;
  }

  const data = JSON.parse(existing);
  const vlessUri = buildVlessUri(data.uuid, host, `${BRAND} • ${data.name}`);

  await sendMessage(chatId,
`${EMOJI_LOGO} <b>Твой ключ ${BRAND}</b>

<b>🔑 VLESS:</b>
<code>${vlessUri}</code>

<b>🔗 Подписка:</b>
<code>https://${host}/sub/${userId}</code>

📅 Создан: ${new Date(data.createdAt).toLocaleDateString("ru-RU")}
📊 Статус: ${data.active ? "✅ Активен" : "❌ Неактивен"}`);
}

async function cmdHelp(chatId: number) {
  await sendMessage(chatId,
`${EMOJI_LOGO} <b>Помощь — ${BRAND}</b>

<b>Команды:</b>
/start — Главное меню
/getkey — Получить VPN-ключ
/mykey — Показать мой ключ
/delete — Удалить ключ
/stats — Статистика
/help — Эта справка

<b>Приложения:</b>
📱 V2RayTUN (рекомендуем)
📱 V2RayNG / Hiddify / Streisand`);
}

async function cmdDeleteKey(chatId: number, userId: string) {
  const existing = await kvGet(`user:${userId}`);
  if (!existing) {
    await sendMessage(chatId, "❌ Нечего удалять.");
    return;
  }

  const data = JSON.parse(existing);
  await kvDel(`user:${userId}`);
  await kvDel(`uuid:${data.uuid}`);

  await sendMessage(chatId, "🗑 <b>Ключ удалён!</b>\n\nНажми /getkey для нового.");
}

async function cmdStats(chatId: number) {
  const keys = await kvKeys("user:");
  await sendMessage(chatId,
`${EMOJI_LOGO} <b>Статистика ${BRAND}</b>

👥 Пользователей: <b>${keys.length}</b>
🌐 Протокол: VLESS + WS + TLS
🔐 DNS: Cloudflare DoH
🦕 Runtime: Deno Deploy
📈 Статус: 🟢 Работает`);
}

// ═════════════════════════════════════════════════════
//  TELEGRAM WEBHOOK
// ═════════════════════════════════════════════════════

async function handleTelegram(request: Request): Promise<Response> {
  let chatId: number | null = null;

  try {
    const body = await request.json();
    const message      = body.message || body.callback_query?.message;
    const callbackData = body.callback_query?.data;
    chatId             = message?.chat?.id;
    const userId       = (body.callback_query?.from?.id || message?.from?.id)?.toString();
    const text         = message?.text || "";
    const host         = new URL(request.url).hostname;

    if (!chatId) return new Response("OK");

    if (callbackData) {
      if (body.callback_query?.id) {
        await tgApi("answerCallbackQuery", { callback_query_id: body.callback_query.id });
      }
      switch (callbackData) {
        case "get_key":    await cmdGetKey(chatId, userId, host); break;
        case "my_key":     await cmdMyKey(chatId, userId, host); break;
        case "help":       await cmdHelp(chatId); break;
        case "delete_key": await cmdDeleteKey(chatId, userId); break;
      }
      return new Response("OK");
    }

    const cmd = text.split(" ")[0].split("@")[0].toLowerCase();
    switch (cmd) {
      case "/start":  await cmdStart(chatId, message.from); break;
      case "/getkey": await cmdGetKey(chatId, userId, host); break;
      case "/mykey":  await cmdMyKey(chatId, userId, host); break;
      case "/help":   await cmdHelp(chatId); break;
      case "/delete": await cmdDeleteKey(chatId, userId); break;
      case "/stats":  await cmdStats(chatId); break;
    }

    return new Response("OK");
  } catch (err) {
    console.error("TG error:", err);
    if (chatId) {
      try {
        await sendMessage(chatId, `⚠️ <b>DEBUG:</b>\n<code>${String(err)}</code>`);
      } catch {}
    }
    return new Response("OK");
  }
}

// ═════════════════════════════════════════════════════
//  SUBSCRIPTION
// ═════════════════════════════════════════════════════

async function handleSubscription(request: Request): Promise<Response> {
  const url    = new URL(request.url);
  const userId = url.pathname.split("/")[2];
  if (!userId) return new Response("Not found", { status: 404 });

  const existing = await kvGet(`user:${userId}`);
  if (!existing) return new Response("No subscription", { status: 404 });

  const data = JSON.parse(existing);
  const host = url.hostname;
  const links = [buildVlessUri(data.uuid, host, `${BRAND} 🌐 Main`)];

  return new Response(buildSubscription(links), {
    headers: {
      "Content-Type":            "text/plain; charset=utf-8",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo":   "upload=0; download=0; total=107374182400; expire=0",
      "Profile-Title":           BRAND,
    },
  });
}

// ═════════════════════════════════════════════════════
//  MAIN ROUTER
// ═════════════════════════════════════════════════════

Deno.serve(async (request: Request): Promise<Response> => {
  const url  = new URL(request.url);
  const path = url.pathname;

  if (path === `/webhook/${BOT_TOKEN}`) {
    return handleTelegram(request);
  }

  if (path.startsWith("/sub/")) {
    return handleSubscription(request);
  }

  if (path === VLESS_PATH) {
    const upgrade = request.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() === "websocket") {
      return handleVlessWs(request);
    }
  }

  if (path === "/" || path === "/health") {
    return new Response(JSON.stringify({
      service: BRAND,
      status: "running",
      features: ["VLESS", "WS", "TLS", "DNS-over-HTTPS"],
      runtime: "Deno Deploy",
      time: new Date().toISOString(),
    }), { headers: { "Content-Type": "application/json" } });
  }

  return new Response("Not Found", { status: 404 });
});
