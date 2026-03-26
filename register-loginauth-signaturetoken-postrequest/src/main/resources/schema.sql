-- Database schema for HTTP Security Authentication System
-- MySQL 8.0+

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS http_security DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE http_security;

-- User table
-- Note: Server manages a single RSA key pair (configured in application.yaml or generated at startup)
-- Client does NOT generate keys - only server generates and manages keys
DROP TABLE IF EXISTS user_http_security;
CREATE TABLE user_http_security (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'User ID',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT 'Username',
    password VARCHAR(255) NOT NULL COMMENT 'Hashed password (SHA-256 with salt)',
    email VARCHAR(100) NOT NULL UNIQUE COMMENT 'Email address',
    salt VARCHAR(255) NOT NULL COMMENT 'Password salt (Base64 encoded)',
    create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Record creation time',
    update_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Record update time',
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User security information table';

-- Nonce table for replay attack prevention (Note: Now using Redis, this table is kept for legacy compatibility)
-- Nonce is now stored in Redis with TTL for automatic expiration
-- DROP TABLE IF EXISTS user_nonce;
-- CREATE TABLE user_nonce (
--     id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'Nonce ID',
--     nonce VARCHAR(100) NOT NULL UNIQUE COMMENT 'Unique nonce value',
--     timestamp BIGINT NOT NULL COMMENT 'Timestamp when nonce was created',
--     create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Record creation time',
--     INDEX idx_nonce (nonce),
--     INDEX idx_timestamp (timestamp)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Nonce table for replay attack prevention';

-- Insert sample data (optional, for testing)
-- Password: test123, Salt: random generated, Hash: SHA-256(password + salt)
-- Note: This is just example data, use proper registration flow in production
