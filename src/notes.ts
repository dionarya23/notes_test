import { Router } from "express";
import { db } from "./db";
import { authMiddleware } from "./auth";

import { NotesUser } from "./types/notes";
import { AuthRequest } from "./types/auth";
import { CreateNoteScheme } from "./scheme/notes";

export const notesRouter = Router();

notesRouter.get("/", authMiddleware, (req: AuthRequest, res) => {
  const { userId } = req.user;
  const result = db
    .prepare(
      `
      SELECT 
        n.id,
        n.user_id,
        n.title,
        n.body,
        u.email as author
      FROM notes n 
      JOIN users u ON n.user_id = u.id
      WHERE n.user_id = ?
    `,
    )
    .get(userId) as NotesUser[];

  res.json(result);
});

notesRouter.get(
  "/:id",
  authMiddleware,
  (req: AuthRequest<{ id: number }>, res) => {
    const { id } = req.params;
    const { userId } = req.user;

    const note = db
      .prepare(`SELECT * FROM notes WHERE id = ? and user_id = ?`)
      .get([id, userId]);

    if (!note) {
      res.status(404).json({
        message: "note not found",
      });
    }

    res.json(note);
  },
);

notesRouter.post("/", authMiddleware, (req: AuthRequest, res) => {
  const parsed = CreateNoteScheme.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const { title, body } = parsed.data;
  const { userId } = req.user;

  const info = db
    .prepare("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)")
    .run(userId, title, body);
  res.json({ id: info.lastInsertRowid });
});
