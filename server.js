const WebSocket = require('ws');
const crypto = require('crypto');
const http = require('http');

const server = http.createServer((req, res) => {
    if (req.url === '/health') {
        res.writeHead(200);
        res.end('OK');
    } else {
        res.writeHead(200);
        res.end('Trypry Messenger Server');
    }
});

const wss = new WebSocket.Server({ server });

// In-memory storage (for production use a real DB like SQLite or MongoDB)
const users = new Map(); // tag -> {tag, displayName, passwordHash, salt}
const sessions = new Map(); // token -> tag
const clients = new Map(); // ws -> {tag, displayName}
const dmHistory = new Map(); // "tagA|tagB" -> [{...}]
const globalHistory = [];

function hashPassword(password, salt) {
    return crypto.createHmac('sha256', salt).update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getTime() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
}

function broadcast(data, excludeWs) {
    const msg = JSON.stringify(data);
    wss.clients.forEach(ws => {
        if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
            ws.send(msg);
        }
    });
}

function sendTo(tag, data) {
    for (const [ws, info] of clients.entries()) {
        if (info.tag === tag && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
            return true;
        }
    }
    return false;
}

function getOnlineUsers() {
    const online = [];
    for (const info of clients.values()) {
        online.push({ tag: info.tag, displayName: info.displayName });
    }
    return online;
}

wss.on('connection', (ws) => {
    console.log('New connection');

    ws.on('message', (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        const { type, payload } = data;

        if (type === 'register') {
            const { tag, displayName, password } = payload;
            if (!tag || !password || tag.length < 3) {
                return ws.send(JSON.stringify({ type: 'error', payload: { message: 'Неверные данные' } }));
            }
            const cleanTag = '@' + tag.toLowerCase().replace(/[^a-z0-9_]/g, '');
            if (users.has(cleanTag)) {
                return ws.send(JSON.stringify({ type: 'error', payload: { message: 'Этот @тег уже занят' } }));
            }
            const salt = crypto.randomBytes(16).toString('hex');
            const passwordHash = hashPassword(password, salt);
            users.set(cleanTag, { tag: cleanTag, displayName: displayName || tag, passwordHash, salt });
            const token = generateToken();
            sessions.set(token, cleanTag);
            clients.set(ws, { tag: cleanTag, displayName: displayName || tag });
            ws.send(JSON.stringify({ type: 'auth_success', payload: { tag: cleanTag, displayName: displayName || tag, token } }));
            broadcast({ type: 'user_online', payload: { tag: cleanTag, displayName: displayName || tag } }, ws);
            ws.send(JSON.stringify({ type: 'online_users', payload: { users: getOnlineUsers() } }));
            console.log('Registered:', cleanTag);
        }

        else if (type === 'login') {
            const { tag, password } = payload;
            const cleanTag = tag.startsWith('@') ? tag.toLowerCase() : '@' + tag.toLowerCase();
            const user = users.get(cleanTag);
            if (!user) {
                return ws.send(JSON.stringify({ type: 'error', payload: { message: 'Пользователь не найден' } }));
            }
            const hash = hashPassword(password, user.salt);
            if (hash !== user.passwordHash) {
                return ws.send(JSON.stringify({ type: 'error', payload: { message: 'Неверный пароль' } }));
            }
            const token = generateToken();
            sessions.set(token, cleanTag);
            clients.set(ws, { tag: cleanTag, displayName: user.displayName });
            ws.send(JSON.stringify({ type: 'auth_success', payload: { tag: cleanTag, displayName: user.displayName, token } }));
            broadcast({ type: 'user_online', payload: { tag: cleanTag, displayName: user.displayName } }, ws);
            ws.send(JSON.stringify({ type: 'online_users', payload: { users: getOnlineUsers() } }));
            // Send last 50 global messages
            ws.send(JSON.stringify({ type: 'history', payload: { messages: globalHistory.slice(-50) } }));
        }

        else if (type === 'global_message') {
            const client = clients.get(ws);
            if (!client) return ws.send(JSON.stringify({ type: 'error', payload: { message: 'Не авторизован' } }));
            const text = payload.text?.trim();
            if (!text || text.length > 500) return;
            const msg = { tag: client.tag, displayName: client.displayName, text, time: getTime(), timestamp: Date.now() };
            globalHistory.push(msg);
            if (globalHistory.length > 500) globalHistory.shift();
            broadcast({ type: 'global_message', payload: msg });
        }

        else if (type === 'dm') {
            const client = clients.get(ws);
            if (!client) return;
            const { toTag, text } = payload;
            if (!text?.trim() || !toTag) return;
            const msg = { from: client.tag, to: toTag, text: text.trim(), time: getTime(), timestamp: Date.now() };
            const key = [client.tag, toTag].sort().join('|');
            if (!dmHistory.has(key)) dmHistory.set(key, []);
            dmHistory.get(key).push(msg);
            // Send to recipient
            sendTo(toTag, { type: 'dm', payload: msg });
            // Echo back to sender
            ws.send(JSON.stringify({ type: 'dm_sent', payload: msg }));
        }

        else if (type === 'get_dm_history') {
            const client = clients.get(ws);
            if (!client) return;
            const { withTag } = payload;
            const key = [client.tag, withTag].sort().join('|');
            const history = dmHistory.get(key) || [];
            ws.send(JSON.stringify({ type: 'dm_history', payload: { withTag, messages: history.slice(-50) } }));
        }
    });

    ws.on('close', () => {
        const client = clients.get(ws);
        if (client) {
            broadcast({ type: 'user_offline', payload: { tag: client.tag } });
            clients.delete(ws);
        }
    });
});

const PORT = process.env.PORT || 8082;
server.listen(PORT, () => console.log(`Trypry Messenger running on port ${PORT}`));
