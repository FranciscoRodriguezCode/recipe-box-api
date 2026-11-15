# End-to-end API Security Audit – 2026-11-15

## 1. Password Storage

- Table: `users`
- Column: `password_hash`
- Sample values (redacted):

  - `scrypt:32768:8:1$...$8d1dc8d2f95b95...`
  - `scrypt:32768:8:1$...$aaf3a6ca7f0b47...`

- Observations:
  - Passwords are stored as long, random-looking hashes with scrypt metadata.
  - No plaintext or human-readable passwords present.

**Result:** PASS ✅

---

## 2. Authentication – Token Requirements

Route audited: `POST /recipes`

- No token:

  ```bash
  POST /recipes
  -> 401 UNAUTHORIZED
  { "error": "Authorization header with Bearer token required" }
  ```

- Invalid token:

  ```bash
  Authorization: Bearer abc.invalid.token
  -> 401 UNAUTHORIZED
  { "error": "invalid token" }
  ```

- Valid token (alice, `sub=1`, role `user`):

  ```bash
  Authorization: Bearer <ALICE_TOKEN>
  -> 201 CREATED
  {
    "id": 2,
    "title": "Alice Recipe",
    "owner_id": 1,
    ...
  }
  ```

**Result:**  
Unauthenticated/invalid tokens are rejected with `401`. Valid token succeeds. PASS ✅

---

## 3. Authorization – Ownership and Admin

### PATCH /recipes/<id>

Test data:

- Recipe `2`: owner_id = 1 (alice, user)
- Recipe `3`: owner_id = 2 (bob, admin)

Results:

- Owner editing own recipe:

  ```bash
  PATCH /recipes/2 as alice (user, sub=1)
  -> 200 OK
  "instructions": "updated by alice"
  ```

- Admin editing someone else’s recipe:

  ```bash
  PATCH /recipes/2 as bob (admin, sub=2)
  -> 200 OK
  "instructions": "admin updated alice recipe"
  ```

- Non-owner, non-admin editing another user’s recipe:

  ```bash
  PATCH /recipes/3 as alice (user, sub=1)
  -> 403 FORBIDDEN
  { "error": "forbidden" }
  ```

**Result:** Only owner or admin can update. Others get `403`. PASS ✅

### DELETE /recipes/<id>

- Owner delete own recipe:

  ```bash
  DELETE /recipes/2 as alice (owner)
  -> 204 NO CONTENT
  ```

- Non-owner, non-admin delete:

  ```bash
  DELETE /recipes/3 as alice (not owner)
  -> 403 FORBIDDEN
  { "error": "forbidden" }
  ```

- Admin delete:

  ```bash
  DELETE /recipes/3 as bob (admin)
  -> 204 NO CONTENT
  ```

**Result:** Delete operations follow same owner/admin rules. PASS ✅

---

## 4. Regression – Previous Exploit Attempts

Earlier in the course it was possible to edit/delete another user’s recipe without proper checks.

Re-run attempt:

- alice (user) trying to modify bob’s recipe:

  ```bash
  PATCH /recipes/3 as alice
  -> 403 FORBIDDEN
  { "error": "forbidden" }
  ```

**Result:** Old cross-user modification exploit is now blocked by authorization checks. PASS ✅

---

## 5. Middleware Coverage

- `@require_auth` is applied to:

  - `PATCH /recipes/<id>`
  - `DELETE /recipes/<id>`

- `POST /recipes` uses explicit JWT verification inline.
- Public read routes (`GET /recipes`, `GET /recipes/<id>`) intentionally have no auth.

**Result:** All write/modify operations are behind authentication + authorization; reads are intentionally public. PASS 

# Security baseline – open API

Date: 2026-11-07

- `GET /recipes` → 200 OK, returns all recipes including `"is_public": false` items like `"Secret family hot sauce"`.
- `POST /recipes` → 201 CREATED, anonymous requester can create a new recipe (e.g. `"Anonymous test recipe"` with id 4).
- `DELETE /recipes/4` → 204 NO CONTENT, anonymous requester can delete an existing recipe; follow-up `GET /recipes` confirms id 4 is gone.
