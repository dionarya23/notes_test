import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { app } from "../src/index";
import { db } from "../src/db";

let aliceToken: string;
let bobToken: string;

beforeAll(async () => {
  const aliceRes = await request(app).post("/auth/login").send({
    email: "alice@example.com",
    password: "password1",
  });
  aliceToken = aliceRes.body.token;

  const bobRes = await request(app).post("/auth/login").send({
    email: "bob@example.com",
    password: "password2",
  });
  bobToken = bobRes.body.token;
});

describe("Access Control on GET /notes", () => {
  it("alice should only see her own notes", async () => {
    const res = await request(app)
      .get("/notes")
      .set("Authorization", `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);

    const notes = Array.isArray(res.body) ? res.body : [res.body];

    for (const note of notes) {
      if (note.user_id !== undefined) {
        expect(note.user_id).toBe(1);
      }
      if (note.author !== undefined) {
        expect(note.author).toBe("alice@example.com");
      }
    }
  });

  it("bob should only see his own notes", async () => {
    const res = await request(app)
      .get("/notes")
      .set("Authorization", `Bearer ${bobToken}`);

    expect(res.status).toBe(200);

    const notes = Array.isArray(res.body) ? res.body : [res.body];

    for (const note of notes) {
      if (note.user_id !== undefined) {
        expect(note.user_id).toBe(2);
      }
      if (note.author !== undefined) {
        expect(note.author).toBe("bob@example.com");
      }
    }
  });

  it("alice should NOT see bob's notes in her response", async () => {
    const res = await request(app)
      .get("/notes")
      .set("Authorization", `Bearer ${aliceToken}`);

    const notes = Array.isArray(res.body) ? res.body : [res.body];

    const hasBobNote = notes.some(
      (n: any) => n.author === "bob@example.com" || n.user_id === 2,
    );
    expect(hasBobNote).toBe(false);
  });
});

describe("Access Control on GET /notes/:id", () => {
  it("alice can access her own note", async () => {
    const res = await request(app)
      .get("/notes/1")
      .set("Authorization", `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);
    expect(res.body.user_id).toBe(1);
  });

  it("alice should NOT be able to access bob's note", async () => {
    const res = await request(app)
      .get("/notes/2")
      .set("Authorization", `Bearer ${aliceToken}`);

    expect(res.status).toBe(404);
  });

  it("bob should NOT be able to access alice's note", async () => {
    const res = await request(app)
      .get("/notes/1")
      .set("Authorization", `Bearer ${bobToken}`);

    expect(res.status).toBe(404);
  });

  it("should return 404 for non-existent note", async () => {
    const res = await request(app)
      .get("/notes/9999")
      .set("Authorization", `Bearer ${aliceToken}`);

    expect(res.status).toBe(404);
  });
});

describe("Notes endpoints require authentication", () => {
  it("GET /notes should return 401 without token", async () => {
    const res = await request(app).get("/notes");
    expect(res.status).toBe(401);
  });

  it("GET /notes/:id should return 401 without token", async () => {
    const res = await request(app).get("/notes/1");
    expect(res.status).toBe(401);
  });

  it("POST /notes should return 401 without token", async () => {
    const res = await request(app)
      .post("/notes")
      .send({ title: "test", body: "test" });
    expect(res.status).toBe(401);
  });

  it("should reject an invalid/tampered token", async () => {
    const res = await request(app)
      .get("/notes")
      .set("Authorization", "Bearer fakeinvalidtoken123");
    expect(res.status).toBe(401);
  });
});

describe("POST /notes", () => {
  it("should create a note for the authenticated user", async () => {
    const res = await request(app)
      .post("/notes")
      .set("Authorization", `Bearer ${aliceToken}`)
      .send({ title: "My Test Note", body: "This is a test" });

    expect(res.status).toBe(200);
    expect(res.body.id).toBeDefined();

    const note = db
      .prepare("SELECT * FROM notes WHERE id = ?")
      .get(res.body.id) as any;
    expect(note.user_id).toBe(1);
    expect(note.title).toBe("My Test Note");
  });

  it("should reject note with missing title", async () => {
    const res = await request(app)
      .post("/notes")
      .set("Authorization", `Bearer ${aliceToken}`)
      .send({ body: "no title here" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });
});
