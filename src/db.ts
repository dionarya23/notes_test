import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import { config } from "./config";

export const db = new Database(config.dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    body TEXT
  );
`);

export function hashPassword(s: string): string {
  const saltRounds = 10;
  return bcrypt.hashSync(s, saltRounds);
}

export function comparePassword(
  password: string,
  hashPassword: string,
): Boolean {
  return bcrypt.compareSync(password, hashPassword);
}

const count = db.prepare("SELECT COUNT(*) as c FROM users").get() as {
  c: number;
};

if (count.c === 0) {
  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    "alice@example.com",
    hashPassword("password1"),
  );
  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    "bob@example.com",
    hashPassword("password2"),
  );
  db.prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)").run(
    1,
    "Alice note",
    "private thoughts",
  );
  db.prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)").run(
    2,
    "Bob note",
    "bob's secrets",
  );
}
