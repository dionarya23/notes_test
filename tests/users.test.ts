import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../src/index";
import { db } from "../src/db";

describe("SQL Injection on /users/register", () => {
  it("should NOT allow registration bypass via SQL injection", async () => {
    const res = await request(app).post("/users/register").send({
      email: "' OR '1'='1' --",
      password: "somepassword",
    });

    expect(res.status).toBe(400);
  });

  it("should NOT allow DROP TABLE via registration email", async () => {
    const res = await request(app).post("/users/register").send({
      email: "'; DROP TABLE users; --",
      password: "somepassword",
    });

    expect(res.status).toBe(400);

    const count = db.prepare("SELECT COUNT(*) as c FROM users").get() as {
      c: number;
    };
    expect(count.c).toBeGreaterThan(0);
  });
});

describe("Input Validation on /users/register", () => {
  it("should reject registration with missing email", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({ password: "password123" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject registration with missing password", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({ email: "test@test.com" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject registration with invalid email format", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({ email: "not-an-email", password: "password123" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject registration with empty body", async () => {
    const res = await request(app).post("/users/register").send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should reject registration with short password", async () => {
    const res = await request(app)
      .post("/users/register")
      .send({ email: "newuser@test.com", password: "12" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });
});

describe("Successful Registration", () => {
  it("should register a new user successfully", async () => {
    const res = await request(app).post("/users/register").send({
      email: "newuser@example.com",
      password: "securepassword",
    });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should reject duplicate email registration", async () => {
    const res = await request(app).post("/users/register").send({
      email: "alice@example.com",
      password: "anotherpassword",
    });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe("email taken");
  });

  it("newly registered user should be able to login", async () => {
    await request(app).post("/users/register").send({
      email: "logintest@example.com",
      password: "testpassword123",
    });

    const loginRes = await request(app).post("/auth/login").send({
      email: "logintest@example.com",
      password: "testpassword123",
    });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.token).toBeDefined();
  });

  it("newly registered user's password should be hashed with bcrypt in DB", async () => {
    await request(app).post("/users/register").send({
      email: "hashcheck@example.com",
      password: "plaintext123",
    });

    const user = db
      .prepare("SELECT password FROM users WHERE email = ?")
      .get("hashcheck@example.com") as { password: string };

    expect(user.password).not.toBe("plaintext123");
  });
});
