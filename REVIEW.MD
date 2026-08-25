# Code Assessment Review

## Blocker

1. SQL Injection issues
   In several queries that take user input and use string interpolation, there is a potential for SQL injection. For example, in the `GET /notes/:id` API, it uses syntax like this: ``db.prepare(`SELECT * FROM users WHERE email = '${email}'`)``

   This is dangerous because a user could execute malicious queries, like deleting tables or other destructive actions.

   To fix this, we can replace all queries using string interpolation with parameterized queries using placeholders, like: `db.prepare("SELECT * FROM users WHERE email = ?").get(email)`

2. Broken access control on notes endpoints
   Looking at the `GET /notes` and `GET /notes/:id` endpoints, the queries fetch all notes without filtering by the `user_id` of the currently logged-in user making the request.

   This is dangerous because it allows a logged-in user to access other people's private notes.

   To resolve this, we can update the query to look like this:
   `db.prepare("SELECT * FROM notes WHERE id = ? AND user_id = ?").get(id, req.user.userId)`

3. Weak password hashing
   During the password hashing process in `(src/db.ts)`, the algorithm used is MD5 without a salt: `crypto.createHash("md5").update(s).digest("hex")`. This is highly insecure because MD5 was designed for checksums and integrity checks, not for storing passwords, making it very easy to brute-force. Furthermore, the lack of a salt means that two users with the exact same password will have identical hashes in the database. For instance, if Bob and Alice both use `password123`, their stored hashes will be the same. This makes cyberattacks like `rainbow table` techniques highly effective; a hacker simply needs to match the leaked hashes against widely available MD5 rainbow tables.

   If this database leaks, almost all user passwords could be cracked instantly. To fix this, we should switch to bcrypt or argon2. Both libraries ensure that the resulting hash for a password is unique, rendering brute-force techniques like rainbow tables useless.

## Should-fix

1. N+1 query in GET /notes
   In this endpoint, there are two queries: the first gets all notes, and the second finds the author who wrote each note. However, the second query is executed inside a loop. So, if there are 100 notes, there will be 100 additional queries just to fetch the author's email. This isn't an issue with a small dataset, but once the data grows, it will become a huge bottleneck because each request could send hundreds of separate queries to the database. This can actually be combined into a single query using a JOIN.

   The fix is simply to combine the two queries into one, and we can also tie it in with the access control fix from above (so the notes are also filtered by `user_id`):

   ```sql
   SELECT notes.*, users.email as author
   FROM notes
   JOIN users ON notes.user_id = users.id
   WHERE notes.user_id = ?
   ```

2. CORS is wide open
   In `index.ts`, there is `cors({ origin: "*", credentials: true })`. This is a bit strange because it allows all origins while setting `credentials: true`. These two settings are actually contradictory when combined, and most browsers will outright reject this configuration. It shows that the CORS setup hasn't been properly thought out.

   To fix this, we can replace `origin: "*"` with an allowlist of trusted origins, for example `["https://frontend-notes.com"]`, instead of leaving it wide open to all origins.

3. No input validation on POST /register and POST /login
   In `users.ts` and `auth.ts`, the email and password are taken directly from `req.body` without checking if the fields exist or if they are the correct data type (string). If the password is empty or not sent at all, it will pass right through to `hashPassword`. That function will then throw an unhandled error, causing the request to crash instead of returning a clear response to the client.

   To fix this, validate the existence, data types, and basic formats of the input before it reaches the database. You can use any validation library (zod, joi, express-validator), but I'd suggest Zod because it's TS-first and can infer types directly from the schema, avoiding duplicate type definitions. For example:

   ```ts
   import { z } from "zod";

   const loginSchema = z.object({
     email: z.string().email(),
     password: z.string().min(1),
   });

   authRouter.post("/login", (req, res) => {
     const parsed = loginSchema.safeParse(req.body);
     if (!parsed.success) {
       return res.status(400).json({ error: parsed.error.issues[0].message });
     }
     const { email, password } = parsed.data;
   });
   ```

4. Missing .env.example and incomplete .gitignore
   The `.gitignore` at the root only excludes `node_modules/`. It doesn't include `.env`, and there is no `.env.example` file documenting which environment variables need to be set. It's a small detail, but this is likely part of the reason why the JWT secret mentioned earlier has a hardcoded fallback; nothing "forces" developers to set up the correct env vars during initial setup. Additionally, if someone creates a real `.env` file to store secrets, it won't be ignored and could accidentally be committed.

   The fix is to add `.env` to `.gitignore`, and then create a `.env.example` filled with placeholders:

   ```.env
   JWT_SECRET=change-me
   DB_PATH=notes.db
   PORT=3000
   ```

## Nice to have

1. Heavy use of any in codebase
   Using `req.body as any`, `req: any` in middleware, and other places. This defeats the entire purpose of using TypeScript in the first place. This becomes obvious when reading `notes.ts`: the JWT payload uses `userId`, but it's easy to mistype it as `id`. Because everything is typed as `any`, TypeScript won't catch or flag the error until runtime.

2. No rate limiting on /auth/login
   Currently, the login endpoint can be hit repeatedly without any restrictions. A quick fix would be adding a rate limit (e.g., max 5 attempts per minute per IP) to prevent brute force attacks.

## If This API Were Going to Production Tomorrow

If this API were going to production tomorrow, I would absolutely insist on fixing the SQL injection vulnerabilities, enforcing strict access control, and upgrading the password hashing mechanism. First, replacing string interpolation with parameterized queries is non-negotiable because the current setup leaves the database wide open to destructive attacks or data theft. Second, we must filter the notes queries by the logged-in user's ID to prevent a massive privacy breach where any user can read someone else's private data. Finally, migrating away from unsalted MD5 to a secure hashing algorithm like bcrypt or argon2 is critical, as the current implementation leaves user credentials entirely defenseless against brute force and rainbow table attacks in the event of a database leak.

## Test Output

```
stdout | tests/notes.test.ts
issued token for alice@example.com eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJpYXQiOjE3ODc2NjYwOTB9.zSTZexRRhAcZ-YOQdmp0KBAHtV_lbPhDS_7Y34zml0A

stdout | tests/notes.test.ts
issued token for bob@example.com eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsImVtYWlsIjoiYm9iQGV4YW1wbGUuY29tIiwiaWF0IjoxNzg3NjY2MDkwfQ.8RNyVQdF6anAc0nLnw-Qm3-I4YjGxHDUaY_MlSgPjkE

stdout | tests/users.test.ts > Successful Registration > newly registered user should be able to login
issued token for logintest@example.com eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjgsImVtYWlsIjoibG9naW50ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNzg3NjY2MDkxfQ.U-h66xeQ3TGgyafUWq556GnIqxphZXnPy0stBjUFm-w

stdout | tests/auth.test.ts > Login Flow /auth/login > should login successfully with correct credentials
issued token for alice@example.com eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJpYXQiOjE3ODc2NjYwOTF9.Jqa-TIPZKW-zVE_SisbbteZUYh59EikF_tCkndcso9c

 ✓ tests/users.test.ts (11) 323ms
   ✓ SQL Injection on /users/register (2)
     ✓ should NOT allow registration bypass via SQL injection
     ✓ should NOT allow DROP TABLE via registration email
   ✓ Input Validation on /users/register (5)
     ✓ should reject registration with missing email
     ✓ should reject registration with missing password
     ✓ should reject registration with invalid email format
     ✓ should reject registration with empty body
     ✓ should reject registration with short password
   ✓ Successful Registration (4)
     ✓ should register a new user successfully
     ✓ should reject duplicate email registration
     ✓ newly registered user should be able to login
     ✓ newly registered user's password should be hashed with bcrypt in DB
 ✓ tests/auth.test.ts (15) 733ms
   ✓ Password Hashing (bcrypt) (4) 567ms
     ✓ should produce different hashes for the same password
     ✓ should still validate both hashes against the original password
     ✓ should NOT validate a wrong password against a hash
     ✓ seeded users alice and bob should have different hashes even if passwords were similar
   ✓ SQL Injection on /auth/login (3)
     ✓ should NOT allow login via SQL injection with always-true condition
     ✓ should NOT allow login via SQL injection with UNION SELECT
     ✓ should NOT allow login via SQL injection attempting to drop table
   ✓ Input Validation on /auth/login (5)
     ✓ should reject login with missing email
     ✓ should reject login with missing password
     ✓ should reject login with invalid email format
     ✓ should reject login with empty body
     ✓ should reject login with password too short (< 6 chars)
   ✓ Login Flow /auth/login (3)
     ✓ should login successfully with correct credentials
     ✓ should reject login with wrong password
     ✓ should reject login with non-existent email
 ✓ tests/notes.test.ts (13)
   ✓ Access Control on GET /notes (3)
     ✓ alice should only see her own notes
     ✓ bob should only see his own notes
     ✓ alice should NOT see bob's notes in her response
   ✓ Access Control on GET /notes/:id (4)
     ✓ alice can access her own note
     ✓ alice should NOT be able to access bob's note
     ✓ bob should NOT be able to access alice's note
     ✓ should return 404 for non-existent note
   ✓ Notes endpoints require authentication (4)
     ✓ GET /notes should return 401 without token
     ✓ GET /notes/:id should return 401 without token
     ✓ POST /notes should return 401 without token
     ✓ should reject an invalid/tampered token
   ✓ POST /notes (2)
     ✓ should create a note for the authenticated user
     ✓ should reject note with missing title

 Test Files  3 passed (3)
      Tests  39 passed (39)
   Start at  20:54:50
   Duration  1.24s (transform 92ms, setup 0ms, collect 894ms, tests 1.24s, environment 1ms, prepare 174ms)
```

## With More Time

If I had more time, I would also fix the CORS configuration to use an explicit origin allowlist, add rate limiting to the login endpoint to prevent brute-force attacks, and improve TypeScript strictness by removing all `any` types across the codebase.
