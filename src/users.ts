import { Router } from "express";
import { db, hashPassword } from "./db";

import { UserScheme } from "./scheme/users";

export const usersRouter = Router();

usersRouter.post("/register", (req, res) => {
  const parsed = UserScheme.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { email, password } = parsed.data;

  const existing = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (existing) {
    return res.status(409).json({ error: "email taken" });
  }

  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    email,
    hashPassword(password),
  );
  res.json({ ok: true });
});
