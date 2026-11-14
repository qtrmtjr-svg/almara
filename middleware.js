import { next } from '@vercel/edge';

const ADMIN_HASH = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';

async function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [ts, sig] = token.split('.');
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(TOKEN_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(ts));
  const expected = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (sig !== expected) return false;
  return (Date.now() - parseInt(ts)) < 7 * 24 * 60 * 60 * 1000;
}

function getCookie(req, name) {
  const cookies = req.headers.get('cookie') || '';
  const match = cookies.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? match[1] : null;
}

export const config = {
  matcher: ['/admin/:path*', '/admin'],
};

export default async function middleware(req) {
  const url = new URL(req.url);
  if (url.pathname === '/admin/login' || url.pathname === '/admin/login.html') {
    return next();
  }

  const token = getCookie(req, 'admin_token') || req.headers.get('x-admin-token');
  const valid = await verifyToken(token);

  if (!valid) {
    const loginUrl = new URL('/admin/login.html', req.url);
    return Response.redirect(loginUrl, 302);
  }

  return next();
}
