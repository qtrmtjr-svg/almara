const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const ADMIN_HASH = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';

function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [ts, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  if (sig !== expected) return false;
  return (Date.now() - parseInt(ts)) < 7 * 24 * 60 * 60 * 1000;
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
  return verifyToken(getCookies(req).admin_token);
}

module.exports = async (req, res) => {
  const ROOT = path.join(__dirname, '..');
  const loginPage = path.join(ROOT, 'admin', 'login.html');

  if (!isAdmin(req)) {
    if (fs.existsSync(loginPage)) {
      const content = fs.readFileSync(loginPage, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(content);
    }
    res.writeHead(302, { 'Location': '/admin/login.html' });
    return res.end();
  }

  const parsed = url.parse(req.url, true);
  let file = parsed.query.file || 'index.html';
  if (file.endsWith('/')) file += 'index.html';
  if (!path.extname(file)) file += '/index.html';

  const fullPath = path.join(ROOT, 'admin', file);
  const normalized = path.normalize(fullPath);
  if (!normalized.startsWith(path.normalize(path.join(ROOT, 'admin')))) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  if (fs.existsSync(fullPath)) {
    const ext = path.extname(fullPath).toLowerCase();
    const MIME = {
      '.html': 'text/html; charset=utf-8', '.css': 'text/css',
      '.js': 'application/javascript', '.png': 'image/png',
      '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
      '.svg': 'image/svg+xml', '.json': 'application/json',
      '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2',
    };
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    return res.end(fs.readFileSync(fullPath));
  }

  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('Not found');
};
