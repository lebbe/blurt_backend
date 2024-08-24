# Use postgres locally on my machine

C:\Program Files\PostgreSQL\16\bin>psql -U postgres

CREATE DATABASE blurt;

\c blurt

CREATE TABLE users (
id SERIAL PRIMARY KEY,
username VARCHAR(50) UNIQUE NOT NULL,
password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE messages (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
message VARCHAR(300) NOT NULL
);
