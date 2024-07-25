CREATE DATABASE user_authentication;

USE user_authentication;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    signup_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    reset_token VARCHAR(255),
    reset_token_expiry DATETIME;
);