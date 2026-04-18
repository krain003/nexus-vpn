// ═══════════════════════════════════════════════════════
//  NEXUS VPN  •  v6.3 FIXED
//  VLESS WS Proxy + Telegram Bot + Subscription
//  + DNS-over-HTTPS + Multi-Upstash + Keep-alive
//  FIXES: webhook auto-register, admin guard, ban system,
//         keep-alive trailing slash, VPN-2 bot skip
// ═══════════════════════════════════════════════════════

const BRAND      = "Nexus VPN";
const EMOJI_LOGO = "🛡";
const VLESS_PATH = "/vless";

const BOT_TOKEN  = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const PROXY_UUID = Deno.env.get("PROXY_UUID") ?? "";
const ADMIN_TGID = Deno.env.get("ADMIN_TGID") ?? "";

// Убираем trailing slash из RENDER_EXTERNAL_URL (фикс VPN-2)
const RENDER_URL = (Deno.env.get("RENDER_EXTERNAL_URL") ?? "").replace(/\/+$/, "");

const LOCAL_REDIS_URL   = Deno.env.get("UPSTASH_REDIS_REST_URL") ?? "";
const LOCAL_REDIS_TOKEN = Deno.env.get("UPSTASH_REDIS_REST_TOKEN") ?? "";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

// ═════════════════════════════════════════════════════
//  ТИПЫ
// ═════════════════════════════════════════════════════

interface RedisTarget {
  url: string;
  token: string;
}

interface ServerInfo {
  id: string;
  host: string;
  flag: string;
  name: string;
}

// ═════════════════════════════════════════════════════
//  ФЛАГИ
// ═════════════════════════════════════════════════════

const FLAGS: Record<string, string> = {
  "DE": "🇩🇪", "US": "🇺🇸", "SG": "🇸🇬", "NL": "🇳🇱",
  "UK": "🇬🇧", "GB": "🇬🇧", "FR": "🇫🇷", "JP": "🇯🇵",
  "AU": "🇦🇺", "CA": "🇨🇦", "RU": "🇷🇺", "KR": "🇰🇷",
  "IN": "🇮🇳", "BR": "🇧🇷", "FI": "🇫🇮", "SE": "🇸🇪",
};

// ═════════════════════════════════════════════════════
//  ПАРСИНГ КОНФИГОВ ИЗ ENV
// ═════════════════════════════════════════════════════

function getRedisTargets(): RedisTarget[] {
  const raw = Deno.env.get("REDIS_TARGETS") ?? "";
  if (!raw) {
    if (LOCAL_REDIS_URL && LOCAL_REDIS_TOKEN) {
      return [{ url: LOCAL_REDIS_URL, token: LOCAL_REDIS_TOKEN }];
    }
    return [];
  }
  return raw.split(",").map((pair) => {
    const [url, token] = pair.split(";");
    return { url: url?.trim() ?? "", token: token?.trim() ?? "" };
  }).filter((t) => t.url && t.token);
}

function getServers(): ServerInfo[] {
  const raw = Deno.env.get("SERVERS_LIST") ?? "";
  if (!raw) return [];
  return raw.split(",").map((item) => {
    const parts = item.split(";");
    if (parts.length < 4) return null;
    const [id, host, countryCode, name] = parts;
    return {
      id: id.trim(),
      host: host.trim(),
      flag: FLAGS[countryCode.trim().toUpperCase()] ?? "🌐",
      name: name.trim(),
    };
  }).filter((s): s is ServerInfo => s !== null && !!s.id && !!s.host);
}

// ═════════════════════════════════════════════════════
//  REDIS OPERATIONS
// ═════════════════════════════════════════════════════

async function redisExec(
  url: string,
  token: string,
  command: string[]
): Promise<unknown> {
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });
  const data = await resp.json();
  return data.result;
}

async function kvGet(key: string): Promise<string | null> {
  if (!LOCAL_REDIS_URL) return null;
  return (await redisExec(LOCAL_REDIS_URL, LOCAL_REDIS_TOKEN, ["GET", key])) as string | null;
}

async function kvSetAll(key: string, value: string): Promise<void> {
  const targets = getRedisTargets();
  await Promise.allSettled(
    targets.map((t) => redisExec(t.url, t.token, ["SET", key, value]))
  );
}

async function kvDelAll(key: string): Promise<void> {
  const targets = getRedisTargets();
  await Promise.allSettled(
    targets.map((t) => redisExec(t.url, t.token, ["DEL", key]))
  );
}

async function kvKeys(prefix: string): Promise<string[]> {
  if (!LOCAL_REDIS_URL) return [];
  return ((await redisExec(LOCAL_REDIS_URL, LOCAL_REDIS_TOKEN, ["KEYS", `${prefix}*`])) as string[]) || [];
}

// ═════════════════════════════════════════════════════
//  УТИЛИТЫ
// ═════════════════════════════════════════════════════

function isAdmin(userId: string | number): boolean {
  return ADMIN_TGID !== "" && String(userId) === String(ADMIN_TGID);
}

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
  command: number;
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
    address = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
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
      parts.push(
        ((data[offset + i * 2] << 8) | data[offset + i * 2 + 1]).toString(16)
      );
    }
    address = parts.join(":");
    offset += 16;
  } else {
    return null;
  }

  return { version, uuid, command, port, address, payload: data.slice(offset) };
}

// ═════════════════════════════════════════════════════
//  UUID АВТОРИЗАЦИЯ + ПРОВЕРКА БАНА
// ═════════════════════════════════════════════════════

async function isUUIDAllowed(clientUUID: Uint8Array): Promise<boolean> {
  const masterBytes = uuidToBytes(PROXY_UUID);
  if (bytesEqual(clientUUID, masterBytes)) return true;

  const uuidStr = bytesToUUID(clientUUID);
  const userId = await kvGet(`uuid:${uuidStr}`);
  if (userId === null) return false;

  // Проверяем бан
  const banned = await kvGet(`ban:${userId}`);
  if (banned !== null) return false;

  return true;
}

// ═════════════════════════════════════════════════════
//  DNS-over-HTTPS
// ═════════════════════════════════════════════════════

async function handleDnsQuery(dnsPayload: Uint8Array): Promise<Uint8Array> {
  try {
    const resp = await fetch(DOH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/dns-message",
        Accept: "application/dns-message",
      },
      body: dnsPayload,
    });
    if (!resp.ok) throw new Error(`DoH: ${resp.status}`);
    return new Uint8Array(await resp.arrayBuffer());
  } catch (err) {
    console.error("DoH error:", err);
    const fail = new Uint8Array(dnsPayload.length);
    fail.set(dnsPayload);
    if (fail.length > 3) {
      fail[2] = 0x81;
      fail[3] = 0x82;
    }
    return fail;
  }
}

function packUdpResponse(data: Uint8Array): Uint8Array {
  const packed = new Uint8Array(2 + data.length);
  packed[0] = (data.length >> 8) & 0xff;
  packed[1] = data.length & 0xff;
  packed.set(data, 2);
  return packed;
}

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
  if (packets.length === 0 && payload.length > 0) {
    packets.push(payload);
  }
  return packets;
}

// ═════════════════════════════════════════════════════
//  VLESS WebSocket PROXY
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

        const allowed = await isUUIDAllowed(parsed.uuid);
        if (!allowed) {
          const resp = new Uint8Array([parsed.version, 0]);
          ws.send(resp.buffer);
          setTimeout(() => {
            try { ws.close(1002, "Unauthorized"); } catch {}
          }, 100);
          return;
        }

        headerParsed = true;

        if (parsed.command === 2) {
          isUdpMode = true;
          ws.send(new Uint8Array([parsed.version, 0]).buffer);
          if (parsed.payload.length > 0) {
            for (const q of unpackUdpPayload(parsed.payload)) {
              const ans = await handleDnsQuery(q);
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(packUdpResponse(ans).buffer);
              }
            }
          }
          return;
        }

        if (parsed.command === 1) {
          try {
            tcpConn = await Deno.connect({
              hostname: parsed.address,
              port: parsed.port,
            });
            ws.send(new Uint8Array([parsed.version, 0]).buffer);
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

        ws.close(1002, "Unsupported command");
        return;
      } else {
        if (isUdpMode) {
          for (const q of unpackUdpPayload(new Uint8Array(rawData))) {
            const ans = await handleDnsQuery(q);
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(packUdpResponse(ans).buffer);
            }
          }
        } else if (tcpConn) {
          try {
            await tcpConn.write(new Uint8Array(rawData));
          } catch {
            try { ws.close(); } catch {}
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
  const resp = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }
  );
  return resp.json();
}

function sendMessage(
  chatId: number | string,
  text: string,
  extra: Record<string, unknown> = {}
) {
  return tgApi("sendMessage", {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    ...extra,
  });
}

// ═════════════════════════════════════════════════════
//  WEBHOOK SETUP (ГЛАВНЫЙ ФИX)
// ═════════════════════════════════════════════════════

async function setupWebhook(): Promise<void> {
  if (!BOT_TOKEN || !RENDER_URL) {
    console.log("[webhook] Пропуск: нет BOT_TOKEN или RENDER_URL");
    return;
  }

  const webhookUrl = `${RENDER_URL}/webhook/${BOT_TOKEN}`;

  try {
    // Проверяем текущий вебхук
    const info = await tgApi("getWebhookInfo", {}) as Record<string, unknown>;
    const currentUrl = (info?.result as Record<string, unknown>)?.url as string ?? "";

    if (currentUrl === webhookUrl) {
      console.log(`[webhook] Уже установлен: ${webhookUrl}`);
      return;
    }

    // Устанавливаем новый вебхук
    const result = await tgApi("setWebhook", {
      url: webhookUrl,
      allowed_updates: ["message", "callback_query"],
      drop_pending_updates: true,
    }) as Record<string, unknown>;

    if (result?.ok) {
      console.log(`[webhook] ✅ Установлен: ${webhookUrl}`);
    } else {
      console.error("[webhook] ❌ Ошибка:", JSON.stringify(result));
    }
  } catch (err) {
    console.error("[webhook] ❌ Исключение:", err);
  }
}

// ═════════════════════════════════════════════════════
//  BOT COMMANDS
// ═════════════════════════════════════════════════════

async function cmdStart(chatId: number, from: Record<string, string>) {
  const name = from.first_name || "друг";
  const servers = getServers();
  const serverList = servers.length > 0
    ? servers.map((s) => `${s.flag} ${s.name}`).join("\n")
    : "🌐 Main Server";

  await sendMessage(
    chatId,
    `${EMOJI_LOGO} <b>Добро пожаловать в ${BRAND}!</b>

Привет, <b>${name}</b>! 👋

Получи <b>бесплатный VPN-ключ</b> для <b>V2RayTUN</b>.

🔹 Безлимитный трафик
🔹 Без логов и рекламы
🔹 Высокая скорость

<b>🌍 Серверы:</b>
${serverList}`,
    {
      reply_markup: {
        inline_keyboard: [
          [{ text: "🔑 Получить ключ", callback_data: "get_key" }],
          [
            { text: "📋 Мой ключ", callback_data: "my_key" },
            { text: "❓ Помощь", callback_data: "help" },
          ],
        ],
      },
    }
  );
}

async function cmdGetKey(chatId: number, userId: string, host: string) {
  // Проверка бана
  const banned = await kvGet(`ban:${userId}`);
  if (banned !== null) {
    await sendMessage(chatId, "🚫 <b>Ваш аккаунт заблокирован.</b>\nОбратитесь к администратору.");
    return;
  }

  const existing = await kvGet(`user:${userId}`);

  if (existing) {
    const data = JSON.parse(existing);
    const servers = getServers();
    const mainLink = servers.length > 0
      ? buildVlessUri(data.uuid, servers[0].host, `${BRAND} ${servers[0].flag} ${servers[0].name}`)
      : buildVlessUri(data.uuid, host, `${BRAND} 🌐 Main`);

    await sendMessage(
      chatId,
      `⚠️ <b>У тебя уже есть ключ!</b>

<code>${mainLink}</code>

🔗 Подписка: <code>https://${host}/sub/${userId}</code>

Хочешь новый? Сначала удали: /delete`
    );
    return;
  }

  const uuid = generateUUID();
  const userData = {
    uuid,
    userId,
    name: `User-${userId.slice(-4)}`,
    createdAt: new Date().toISOString(),
    active: true,
  };

  await kvSetAll(`user:${userId}`, JSON.stringify(userData));
  await kvSetAll(`uuid:${uuid}`, userId);

  const servers = getServers();
  const mainLink = servers.length > 0
    ? buildVlessUri(uuid, servers[0].host, `${BRAND} ${servers[0].flag} ${servers[0].name}`)
    : buildVlessUri(uuid, host, `${BRAND} 🌐 Main`);

  const serverList = servers.length > 0
    ? servers.map((s) => `  ${s.flag} ${s.name}`).join("\n")
    : "  🌐 Main";

  await sendMessage(
    chatId,
    `${EMOJI_LOGO} <b>Твой ключ ${BRAND} готов!</b>

<b>🔑 VLESS-ключ:</b>
<code>${mainLink}</code>

<b>🔗 Подписка (${servers.length || 1} серверов):</b>
<code>https://${host}/sub/${userId}</code>

<b>🌍 Серверы:</b>
${serverList}

━━━━━━━━━━━━━━━━
<b>📲 Подключение:</b>

1️⃣ Скачай <b>V2RayTUN</b>
2️⃣ Скопируй ссылку подписки
3️⃣ V2RayTUN → ➕ → Подписка
4️⃣ Вставь ссылку → Сохрани
━━━━━━━━━━━━━━━━`,
    {
      reply_markup: {
        inline_keyboard: [
          [{ text: "📋 Мой ключ", callback_data: "my_key" }],
          [{ text: "🗑 Удалить ключ", callback_data: "delete_key" }],
        ],
      },
    }
  );
}

async function cmdMyKey(chatId: number, userId: string, host: string) {
  const existing = await kvGet(`user:${userId}`);
  if (!existing) {
    await sendMessage(chatId, "❌ Ключа нет.\nНажми /getkey чтобы получить.");
    return;
  }

  const data = JSON.parse(existing);
  const servers = getServers();
  const mainLink = servers.length > 0
    ? buildVlessUri(data.uuid, servers[0].host, `${BRAND} ${servers[0].flag} ${servers[0].name}`)
    : buildVlessUri(data.uuid, host, `${BRAND} 🌐 Main`);

  await sendMessage(
    chatId,
    `${EMOJI_LOGO} <b>Твой ключ ${BRAND}</b>

<b>🔑 VLESS:</b>
<code>${mainLink}</code>

<b>🔗 Подписка:</b>
<code>https://${host}/sub/${userId}</code>

📅 Создан: ${new Date(data.createdAt).toLocaleDateString("ru-RU")}
📊 Статус: ${data.active ? "✅ Активен" : "❌ Неактивен"}`
  );
}

async function cmdHelp(chatId: number) {
  const servers = getServers();
  const serverList = servers.length > 0
    ? servers.map((s) => `${s.flag} ${s.name}`).join("\n")
    : "🌐 Main";

  await sendMessage(
    chatId,
    `${EMOJI_LOGO} <b>Помощь — ${BRAND}</b>

<b>Команды:</b>
/start — Главное меню
/getkey — Получить VPN-ключ
/mykey — Показать мой ключ
/delete — Удалить ключ
/stats — Статистика
/help — Эта справка

<b>🌍 Серверы:</b>
${serverList}

<b>Приложения:</b>
📱 V2RayTUN / V2RayNG / Hiddify`
  );
}

async function cmdDeleteKey(chatId: number, userId: string) {
  const existing = await kvGet(`user:${userId}`);
  if (!existing) {
    await sendMessage(chatId, "❌ Нечего удалять.");
    return;
  }

  const data = JSON.parse(existing);
  await kvDelAll(`user:${userId}`);
  await kvDelAll(`uuid:${data.uuid}`);

  await sendMessage(chatId, "🗑 <b>Ключ удалён!</b>\n\nНажми /getkey для нового.");
}

// ═════════════════════════════════════════════════════
//  ADMIN COMMANDS
// ═════════════════════════════════════════════════════

async function cmdStats(chatId: number, userId: string) {
  // Только для администратора
  if (!isAdmin(userId)) {
    await sendMessage(chatId, "⛔ Нет доступа.");
    return;
  }

  const keys = await kvKeys("user:");
  const banKeys = await kvKeys("ban:");
  const servers = getServers();
  const targets = getRedisTargets();

  await sendMessage(
    chatId,
    `${EMOJI_LOGO} <b>Статистика ${BRAND}</b>

👥 Пользователей: <b>${keys.length}</b>
🚫 Заблокировано: <b>${banKeys.length}</b>
🌍 Серверов: <b>${servers.length || 1}</b>
🗄 Баз данных: <b>${targets.length}</b>
🌐 Протокол: VLESS + WS + TLS
📈 Статус: 🟢 Работает`
  );
}

// /ban <userId>  — заблокировать пользователя
async function cmdBan(chatId: number, adminId: string, text: string) {
  if (!isAdmin(adminId)) {
    await sendMessage(chatId, "⛔ Нет доступа.");
    return;
  }

  const targetId = text.split(" ")[1]?.trim();
  if (!targetId) {
    await sendMessage(chatId, "⚠️ Использование: /ban <user_id>");
    return;
  }

  const existing = await kvGet(`user:${targetId}`);
  if (!existing) {
    await sendMessage(chatId, `❌ Пользователь <code>${targetId}</code> не найден.`);
    return;
  }

  const userData = JSON.parse(existing);
  userData.active = false;
  await kvSetAll(`user:${targetId}`, JSON.stringify(userData));
  await kvSetAll(`ban:${targetId}`, "1");
  // Удаляем UUID из разрешённых — VPN перестанет работать
  await kvDelAll(`uuid:${userData.uuid}`);

  await sendMessage(chatId, `🚫 Пользователь <code>${targetId}</code> заблокирован. VPN-ключ деактивирован.`);
}

// /unban <userId>  — разблокировать пользователя
async function cmdUnban(chatId: number, adminId: string, text: string) {
  if (!isAdmin(adminId)) {
    await sendMessage(chatId, "⛔ Нет доступа.");
    return;
  }

  const targetId = text.split(" ")[1]?.trim();
  if (!targetId) {
    await sendMessage(chatId, "⚠️ Использование: /unban <user_id>");
    return;
  }

  const existing = await kvGet(`user:${targetId}`);
  if (!existing) {
    await sendMessage(chatId, `❌ Пользователь <code>${targetId}</code> не найден.`);
    return;
  }

  const userData = JSON.parse(existing);
  userData.active = true;
  await kvSetAll(`user:${targetId}`, JSON.stringify(userData));
  await kvDelAll(`ban:${targetId}`);
  // Восстанавливаем UUID → userId маппинг
  await kvSetAll(`uuid:${userData.uuid}`, targetId);

  await sendMessage(chatId, `✅ Пользователь <code>${targetId}</code> разблокирован. VPN-ключ восстановлен.`);
}

// /userinfo <userId>  — информация о пользователе
async function cmdUserInfo(chatId: number, adminId: string, text: string) {
  if (!isAdmin(adminId)) {
    await sendMessage(chatId, "⛔ Нет доступа.");
    return;
  }

  const targetId = text.split(" ")[1]?.trim();
  if (!targetId) {
    await sendMessage(chatId, "⚠️ Использование: /userinfo <user_id>");
    return;
  }

  const existing = await kvGet(`user:${targetId}`);
  if (!existing) {
    await sendMessage(chatId, `❌ Пользователь <code>${targetId}</code> не найден.`);
    return;
  }

  const data = JSON.parse(existing);
  const banned = await kvGet(`ban:${targetId}`);

  await sendMessage(
    chatId,
    `👤 <b>Пользователь ${targetId}</b>

UUID: <code>${data.uuid}</code>
Создан: ${new Date(data.createdAt).toLocaleDateString("ru-RU")}
Статус: ${data.active ? "✅ Активен" : "❌ Неактивен"}
Бан: ${banned !== null ? "🚫 Да" : "✅ Нет"}`
  );
}

// /deluser <userId>  — принудительно удалить ключ пользователя
async function cmdDelUser(chatId: number, adminId: string, text: string) {
  if (!isAdmin(adminId)) {
    await sendMessage(chatId, "⛔ Нет доступа.");
    return;
  }

  const targetId = text.split(" ")[1]?.trim();
  if (!targetId) {
    await sendMessage(chatId, "⚠️ Использование: /deluser <user_id>");
    return;
  }

  const existing = await kvGet(`user:${targetId}`);
  if (!existing) {
    await sendMessage(chatId, `❌ Пользователь <code>${targetId}</code> не найден.`);
    return;
  }

  const data = JSON.parse(existing);
  await kvDelAll(`user:${targetId}`);
  await kvDelAll(`uuid:${data.uuid}`);
  await kvDelAll(`ban:${targetId}`);

  await sendMessage(chatId, `🗑 Данные пользователя <code>${targetId}</code> удалены.`);
}

// ═════════════════════════════════════════════════════
//  TELEGRAM WEBHOOK
// ═════════════════════════════════════════════════════

async function handleTelegram(request: Request): Promise<Response> {
  if (!BOT_TOKEN) return new Response("Bot not configured", { status: 200 });

  let chatId: number | null = null;

  try {
    const body = await request.json();
    const message      = body.message || body.callback_query?.message;
    const callbackData = body.callback_query?.data;
    chatId             = message?.chat?.id;
    const userId       = (body.callback_query?.from?.id || message?.from?.id)?.toString();
    const text         = message?.text || "";
    const host         = new URL(request.url).hostname;

    if (!chatId || !userId) return new Response("OK");

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
      case "/start":    await cmdStart(chatId, message.from); break;
      case "/getkey":   await cmdGetKey(chatId, userId, host); break;
      case "/mykey":    await cmdMyKey(chatId, userId, host); break;
      case "/help":     await cmdHelp(chatId); break;
      case "/delete":   await cmdDeleteKey(chatId, userId); break;
      // Только для админа:
      case "/stats":    await cmdStats(chatId, userId); break;
      case "/ban":      await cmdBan(chatId, userId, text); break;
      case "/unban":    await cmdUnban(chatId, userId, text); break;
      case "/userinfo": await cmdUserInfo(chatId, userId, text); break;
      case "/deluser":  await cmdDelUser(chatId, userId, text); break;
    }

    return new Response("OK");
  } catch (err) {
    console.error("TG error:", err);
    if (chatId) {
      try {
        await sendMessage(chatId, `⚠️ <b>Ошибка:</b>\n<code>${String(err)}</code>`);
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

  // Проверка бана при запросе подписки
  const banned = await kvGet(`ban:${userId}`);
  if (banned !== null) return new Response("Forbidden", { status: 403 });

  const data    = JSON.parse(existing);
  const host    = url.hostname;
  const servers = getServers();

  const links = servers.length > 0
    ? servers.map((s) => buildVlessUri(data.uuid, s.host, `${BRAND} ${s.flag} ${s.name}`))
    : [buildVlessUri(data.uuid, host, `${BRAND} 🌐 Main`)];

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
//  KEEP-ALIVE (с защитой от trailing slash)
// ═════════════════════════════════════════════════════

if (RENDER_URL) {
  setInterval(async () => {
    try {
      await fetch(`${RENDER_URL}/health`);
      console.log("[keep-alive] OK →", RENDER_URL);
    } catch (e) {
      console.error("[keep-alive] FAIL:", e);
    }
  }, 10 * 60 * 1000);
}

// ═════════════════════════════════════════════════════
//  MAIN ROUTER
// ═════════════════════════════════════════════════════

// Регистрируем вебхук при старте (только если есть токен и URL)
if (BOT_TOKEN && RENDER_URL) {
  setupWebhook();
}

Deno.serve({ port: 8000 }, async (request: Request): Promise<Response> => {
  const url  = new URL(request.url);
  const path = url.pathname;

  if (BOT_TOKEN && path === `/webhook/${BOT_TOKEN}`) {
    return handleTelegram(request);
  }

  if (path.startsWith("/sub/")) {
    return handleSubscription(request);
  }

  if (path === VLESS_PATH) {
    const upgrade = request.headers.get("upgrade") ?? "";
    if (upgrade.toLowerCase() === "websocket") {
      return handleVlessWs(request);
    }
  }

  if (path === "/" || path === "/health") {
    const servers = getServers();
    return new Response(
      JSON.stringify({
        service: BRAND,
        status:  "running",
        servers: servers.length || 1,
        time:    new Date().toISOString(),
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  return new Response("Not Found", { status: 404 });
});
