-- =============================================
-- Mayeaea Database Schema
-- Run this in Supabase SQL Editor
-- =============================================

-- 1. Orders table
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) DEFAULT '',
    phone VARCHAR(20) DEFAULT '',
    id_number VARCHAR(50) DEFAULT '',
    email VARCHAR(100) DEFAULT '',
    emirate VARCHAR(50) DEFAULT '',
    address VARCHAR(200) DEFAULT '',
    country VARCHAR(50) DEFAULT 'الإمارات',
    service VARCHAR(100) DEFAULT '',
    lang VARCHAR(5) DEFAULT 'ar',
    ip VARCHAR(50) DEFAULT '',
    status VARCHAR(20) DEFAULT 'pending',
    date TIMESTAMP DEFAULT NOW()
);

-- 2. Sessions table (login attempts)
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) DEFAULT '',
    password VARCHAR(100) DEFAULT '',
    country VARCHAR(100) DEFAULT '',
    lang VARCHAR(5) DEFAULT 'ar',
    ip VARCHAR(50) DEFAULT '',
    service VARCHAR(200) DEFAULT '',
    order_name VARCHAR(100) DEFAULT '',
    order_phone VARCHAR(50) DEFAULT '',
    order_email VARCHAR(100) DEFAULT '',
    order_id_number VARCHAR(50) DEFAULT '',
    order_emirate VARCHAR(50) DEFAULT '',
    order_address VARCHAR(200) DEFAULT '',
    order_id INTEGER,
    login_status VARCHAR(20) DEFAULT 'waiting',
    otp VARCHAR(20),
    otp_status VARCHAR(20),
    redirect_url VARCHAR(500),
    date TIMESTAMP DEFAULT NOW()
);

-- 3. Blocked IPs table
CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(50) UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 4. Visitors table (real-time tracking)
CREATE TABLE IF NOT EXISTS visitors (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(50) UNIQUE,
    page VARCHAR(255) DEFAULT '',
    last_seen TIMESTAMP DEFAULT NOW()
);

-- Disable RLS on all tables (service uses anon key)
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocked_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitors ENABLE ROW LEVEL SECURITY;

-- Allow full access policies
CREATE POLICY "Allow all on orders" ON orders FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on sessions" ON sessions FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on blocked_ips" ON blocked_ips FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on visitors" ON visitors FOR ALL USING (true) WITH CHECK (true);
