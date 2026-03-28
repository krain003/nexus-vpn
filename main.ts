// ═══════════════════════════════════════════════════════
//  NEXUS VPN  •  Deno Deploy  v3.0
//  VLESS WS Proxy + Telegram Bot + Subscription
//  Совместимо с V2RayTUN / V2RayNG / Hiddify / Streisand
// ═══════════════════════════════════════════════════════

const BRAND      = "Nexus VPN";
const EMOJI_LOGO = "🛡";
const VLESS_PATH = "/vless";

// ─── Env ─────────────────────────────────────────────
const BOT_TOKEN  = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const PROXY_UUID = Deno.env.get("PROXY_UUID") ?? "";
const ADMIN_TGID = Deno.env.get("ADMIN_TGID") ?? "";

// ─── Deno KV (встроен в Deno Deploy, 0 настройки) ───
const kv = await Deno.openKv();

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
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
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
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
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

  const command = data[offset++]; // 1=TCP, 2=UDP
  const port    = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  const addrType = data[offset++];
  let address = "";

  if (addrType === 1) {
    // IPv4
    if (offset + 4 > data.length) return null;
    address = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    offset += 4;
  } else if (addrType === 2) {
    // Domain
    const domainLen = data[offset++];
    if (offset + domainLen > data.length) return null;
    address = new TextDecoder().decode(data.slice(offset, offset + domainLen));
    offset += domainLen;
  } else if (addrType === 3) {
    // IPv6
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

  const payload = data.slice(offset);
  return { version, uuid, command, port, address, payload };
}

// ═════════════════════════════════════════════════════
//  UUID АВТОРИЗАЦИЯ
// ═════════════════════════════════════════════════════

async function isUUIDAllowed(clientUUID: Uint8Array): Promise<boolean> {
  // 1) Проверяем мастер-UUID
  const masterBytes = uuidToBytes(PROXY_UUID);
  if (bytesEqual(clientUUID, masterBytes)) return true;

  // 2) Ищем в KV
  const uuidStr = bytesToUUID(clientUUID);
  const result = await kv.get(["uuid", uuidStr]);
  return result.value !== null;
}

// ═════════════════════════════════════════════════════
//  VLESS WebSocket PROXY
// ═════════════════════════════════════════════════════

function handleVlessWs(request: Request): Response {
  const { socket: ws, response } = Deno.upgradeWebSocket(request, {
    // Принимаем бинарные данные
  });

  let headerParsed = false;
  let tcpConn: Deno.TcpConn | null = null;

  ws.onmessage = async (event: MessageEvent) => {
    try {
      // Получаем ArrayBuffer
      let rawData: ArrayBuffer;
      if (event.data instanceof ArrayBuffer) {
        rawData = event.data;
      } else if (event.data instanceof Blob) {
        rawData = await event.data.arrayBuffer();
      } else {
        return;
      }

      if (!headerParsed) {
        // ─── Парсим VLESS заголовок ───
        const parsed = parseVlessHeader(rawData);
        if (!parsed) {
          ws.close(1002, "Invalid VLESS header");
          return;
        }

        // ─── Проверяем UUID ───
        const allowed = await isUUIDAllowed(parsed.uuid);
        if (!allowed) {
          const resp = new Uint8Array([parsed.version, 0]);
          ws.send(resp.buffer);
          setTimeout(() => {
            try { ws.close(1002, "Unauthorized"); } catch { /* ok */ }
          }, 100);
          return;
        }

        if (parsed.command !== 1) {
          ws.close(1002, "Only TCP supported");
          return;
        }

        headerParsed = true;

        // ─── Подключаемся к цели ───
        try {
          tcpConn = await Deno.connect({
            hostname: parsed.address,
            port: parsed.port,
          });

          // Отправляем VLESS response header
          const responseHeader = new Uint8Array([parsed.version, 0]);
          ws.send(responseHeader.buffer);

          // Отправляем первый payload
          if (parsed.payload.length > 0) {
            await tcpConn.write(parsed.payload);
          }

          // ─── TCP → WS (чтение из TCP, отправка в WS) ───
          pipeTcpToWs(tcpConn, ws);

        } catch (err) {
          console.error("TCP connect failed:", err);
          ws.close(1002, "TCP connect failed");
          return;
        }
      } else {
        // ─── Последующие пакеты: WS → TCP ───
        if (tcpConn) {
          try {
            await tcpConn.write(new Uint8Array(rawData));
          } catch {
            try { ws.close(); } catch { /* ok */ }
          }
        }
      }
    } catch (e) {
      console.error("WS message error:", e);
      try { ws.close(); } catch { /* ok */ }
    }
  };

  ws.onclose = () => {
    try { tcpConn?.close(); } catch { /* ok */ }
  };

  ws.onerror = () => {
    try { tcpConn?.close(); } catch { /* ok */ }
  };

  return response;
}

async function pipeTcpToWs(tcp: Deno.TcpConn, ws: WebSocket): Promise<void> {
  const buffer = new Uint8Array(16384); // 16KB буфер
  try {
    while (true) {
      const bytesRead = await tcp.read(buffer);
      if (bytesRead === null) break; // EOF
      if (ws.readyState !== WebSocket.OPEN) break;
      ws.send(buffer.slice(0, bytesRead));
    }
  } catch {
    // TCP read error — нормально при закрытии
  } finally {
    try { ws.close(); } catch { /* ok */ }
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
//  TELEGRAM BOT COMMANDS
// ═════════════════════════════════════════════════════

async function cmdStart(chatId: number, from: Record<string, string>) {
  const name = from.first_name || "друг";
  const msg = `${EMOJI_LOGO} <b>Добро пожаловать в ${BRAND}!</b>

Привет, <b>${name}</b>! 👋

Здесь ты можешь получить <b>бесплатный VPN-ключ</b> для <b>V2RayTUN</b>.

🔹 Безлимитный трафик
🔹 Без логов и рекламы
🔹 Высокая скорость

Нажми кнопку ниже, чтобы начать 👇`;

  await sendMessage(chatId, msg, {
    reply_markup: {
      inline_keyboard: [
        [{ text: "🔑 Получить ключ", callback_data: "get_key" }],
        [
          { text: "📋 Мой ключ", callback_data: "my_key" },
          { text: "❓ Помощь", callback_data: "help" },
        ],
      ],
    },
  });
}

async function cmdGetKey(chatId: number, userId: string, host: string) {
  // Проверяем существующий ключ
  const existing = await kv.get(["user", userId]);
  if (existing.value) {
    const data = existing.value as Record<string, string>;
    const vlessUri = buildVlessUri(
      data.uuid,
      host,
      `${BRAND} • ${data.name}`
    );
    await sendMessage(chatId,
      `⚠️ <b>У тебя уже есть ключ!</b>

<code>${vlessUri}</code>

🔗 Подписка: <code>https://${host}/sub/${userId}</code>

Хочешь новый? Сначала удали: /delete`
    );
    return;
  }

  // Генерируем новый
  const uuid = generateUUID();
  const userData = {
    uuid,
    userId,
    name: `User-${userId.slice(-4)}`,
    createdAt: new Date().toISOString(),
    active: true,
  };

  // Сохраняем (атомарная транзакция!)
  await kv.atomic()
    .set(["user", userId], userData)
    .set(["uuid", uuid], userId)
    .commit();

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

<b>Или через подписку:</b>
V2RayTUN → ➕ → Подписка → Вставь ссылку
━━━━━━━━━━━━━━━━`,
    {
      reply_markup: {
        inline_keyboard: [
          [{ text: "📋 Мой ключ", callback_data: "my_key" }],
          [{ text: "🗑 Удалить и пересоздать", callback_data: "delete_key" }],
        ],
      },
    }
  );
}

async function cmdMyKey(chatId: number, userId: string, host: string) {
  const existing = await kv.get(["user", userId]);
  if (!existing.value) {
    await sendMessage(chatId, "❌ Ключа нет.\nНажми /getkey чтобы получить.");
    return;
  }

  const data = existing.value as Record<string, string>;
  const vlessUri = buildVlessUri(data.uuid, host, `${BRAND} • ${data.name}`);

  await sendMessage(chatId,
    `${EMOJI_LOGO} <b>Твой ключ ${BRAND}</b>

<b>🔑 VLESS:</b>
<code>${vlessUri}</code>

<b>🔗 Подписка:</b>
<code>https://${host}/sub/${userId}</code>

📅 Создан: ${new Date(data.createdAt).toLocaleDateString("ru-RU")}
📊 Статус: ${data.active ? "✅ Активен" : "❌ Неактивен"}`
  );
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
📱 V2RayNG / Hiddify / Streisand

<b>Инструкция:</b>
1. Получи ключ: /getkey
2. Скопируй VLESS-ссылку
3. V2RayTUN → ➕ → Импорт из буфера
4. Подключайся! 🎉`
  );
}

async function cmdDeleteKey(chatId: number, userId: string) {
  const existing = await kv.get(["user", userId]);
  if (!existing.value) {
    await sendMessage(chatId, "❌ Нечего удалять.");
    return;
  }

  const data = existing.value as Record<string, string>;

  // Удаляем атомарно
  await kv.atomic()
    .delete(["user", userId])
    .delete(["uuid", data.uuid])
    .commit();

  await sendMessage(chatId,
    `🗑 <b>Ключ удалён!</b>\n\nНажми /getkey для нового.`
  );
}

async function cmdStats(chatId: number) {
  let count = 0;
  const iter = kv.list({ prefix: ["user"] });
  for await (const _entry of iter) {
    count++;
  }

  await sendMessage(chatId,
    `${EMOJI_LOGO} <b>Статистика ${BRAND}</b>

👥 Пользователей: <b>${count}</b>
🌐 Протокол: VLESS + WS + TLS
🦕 Runtime: Deno Deploy
📈 Статус: 🟢 Работает`
  );
}

// ═════════════════════════════════════════════════════
//  TELEGRAM WEBHOOK HANDLER
// ═════════════════════════════════════════════════════

async function handleTelegram(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const message      = body.message || body.callback_query?.message;
    const callbackData = body.callback_query?.data;
    const chatId       = message?.chat?.id;
    const userId       = (body.callback_query?.from?.id || message?.from?.id)?.toString();
    const text         = message?.text || "";
    const host         = new URL(request.url).hostname;

    if (!chatId) return new Response("OK");

    // ── Callback кнопки ──
    if (callbackData) {
      if (body.callback_query?.id) {
        await tgApi("answerCallbackQuery", {
          callback_query_id: body.callback_query.id,
        });
      }

      switch (callbackData) {
        case "get_key":    await cmdGetKey(chatId, userId, host); break;
        case "my_key":     await cmdMyKey(chatId, userId, host); break;
        case "help":       await cmdHelp(chatId); break;
        case "delete_key": await cmdDeleteKey(chatId, userId); break;
      }
      return new Response("OK");
    }

    // ── Текстовые команды ──
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
    console.error("Telegram error:", err);
    return new Response("OK");
  }
}

// ═════════════════════════════════════════════════════
//  SUBSCRIPTION ENDPOINT
// ═════════════════════════════════════════════════════

async function handleSubscription(request: Request): Promise<Response> {
  const url    = new URL(request.url);
  const userId = url.pathname.split("/")[2];

  if (!userId) return new Response("Not found", { status: 404 });

  const existing = await kv.get(["user", userId]);
  if (!existing.value) return new Response("No subscription", { status: 404 });

  const data = existing.value as Record<string, string>;
  const host = url.hostname;

  const links = [
    buildVlessUri(data.uuid, host, `${BRAND} 🌐 Main`),
  ];

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

Deno.serve({ port: 8000 }, async (request: Request): Promise<Response> => {
  const url  = new URL(request.url);
  const path = url.pathname;

  // 1. Telegram Webhook
  if (path === `/webhook/${BOT_TOKEN}`) {
    return handleTelegram(request);
  }

  // 2. Подписка
  if (path.startsWith("/sub/")) {
    return handleSubscription(request);
  }

  // 3. VLESS WebSocket
  if (path === VLESS_PATH) {
    const upgrade = request.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() === "websocket") {
      return handleVlessWs(request);
    }
  }

  // 4. Health check
  if (path === "/" || path === "/health") {
    return new Response(
      JSON.stringify({
        service: BRAND,
        status: "running",
        runtime: "Deno Deploy",
        time: new Date().toISOString(),
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  return new Response("Not Found", { status: 404 });
});
