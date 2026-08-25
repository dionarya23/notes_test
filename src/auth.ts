import { Router } from "express";
import jwt from "jsonwebtoken";

import { db, comparePassword } from "./db";
import { config } from "./config";
import { UserScheme } from "./scheme/users";
import { User } from "./types/auth";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  const parsed = UserScheme.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const { email, password } = parsed.data;
  const row = db
    .prepare(`SELECT id, email, password FROM users WHERE email = ?`)
    .get(email) as User;

  if (!row) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const isPasswordValid = comparePassword(password, row.password);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const token = jwt.sign(
    { userId: row.id, email: row.email },
    config.jwtSecret,
  );
  console.log("issued token for", email, token);
  res.json({ token });
});

export function authMiddleware(req: any, res: any, next: any) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
}
