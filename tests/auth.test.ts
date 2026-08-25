import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { app } from "../src/index";
import { hashPassword, comparePassword, db } from "../src/db";

describe("Password Hashing (bcrypt)", () => {
  it("should produce different hashes for the same password", () => {
    const password = "password123";
    const hash1 = hashPassword(password);
    const hash2 = hashPassword(password);

    expect(hash1).not.toBe(hash2);
  });

  it("should still validate both hashes against the original password", () => {
    const password = "password123";
    const hash1 = hashPassword(password);
    const hash2 = hashPassword(password);

    expect(comparePassword(password, hash1)).toBe(true);
    expect(comparePassword(password, hash2)).toBe(true);
  });

  it("should NOT validate a wrong password against a hash", () => {
    const hash = hashPassword("correctpassword");
    expect(comparePassword("wrongpassword", hash)).toBe(false);
  });

  it("seeded users alice and bob should have different hashes even if passwords were similar", () => {
    const alice = db
      .prepare("SELECT password FROM users WHERE email = ?")
      .get("alice@example.com") as { password: string };
    const bob = db
      .prepare("SELECT password FROM users WHERE email = ?")
      .get("bob@example.com") as { password: string };

    expect(alice.password).toMatch(/^\$2[aby]\$/);
    expect(bob.password).toMatch(/^\$2[aby]\$/);

    expect(alice.password).not.toBe(bob.password);
  });
});

describe("SQL Injection on /auth/login", () => {
  it("should NOT allow login via SQL injection with always-true condition", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "' OR '1'='1' --",
      password: "anything",
    });

    expect([400, 401]).toContain(res.status);
    expect(res.body.token).toBeUndefined();
  });

  it("should NOT allow login via SQL injection with UNION SELECT", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "' UNION SELECT 1, 'admin@test.com', 'fake' --",
      password: "anything",
    });

    expect([400, 401]).toContain(res.status);
    expect(res.body.token).toBeUndefined();
  });

  it("should NOT allow login via SQL injection attempting to drop table", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "'; DROP TABLE users; --",
      password: "anything",
    });

    expect([400, 401]).toContain(res.status);
    expect(res.body.token).toBeUndefined();

    const count = db.prepare("SELECT COUNT(*) as c FROM users").get() as {
      c: number;
    };
    expect(count.c).toBeGreaterThan(0);
  });
});

describe("Input Validation on /auth/login", () => {
  it("should reject login with missing email", async () => {
    const res = await request(app).post("/auth/login").send({
      password: "password1",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject login with missing password", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "alice@example.com",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject login with invalid email format", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "not-an-email",
      password: "password1",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject login with empty body", async () => {
    const res = await request(app).post("/auth/login").send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject login with password too short (< 6 chars)", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "alice@example.com",
      password: "ab",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });
});

describe("Login Flow /auth/login", () => {
  it("should login successfully with correct credentials", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "alice@example.com",
      password: "password1",
    });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(typeof res.body.token).toBe("string");
  });

  it("should reject login with wrong password", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "alice@example.com",
      password: "wrongpassword",
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid credentials");
    expect(res.body.token).toBeUndefined();
  });

  it("should reject login with non-existent email", async () => {
    const res = await request(app).post("/auth/login").send({
      email: "nonexistent@example.com",
      password: "password1",
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid credentials");
  });
});
