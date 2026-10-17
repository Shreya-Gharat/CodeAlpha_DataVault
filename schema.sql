CREATE DATABASE IF NOT EXISTS vaultdb;
USE vaultdb;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,   -- bcrypt hash (one-way), never encrypted
  sensitive_enc TEXT NOT NULL,           -- AES-256-GCM ciphertext (reversible, key held only by the app)
  role ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(64),
  route VARCHAR(100),
  field_name VARCHAR(50),
  payload TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
