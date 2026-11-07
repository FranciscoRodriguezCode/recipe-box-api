# Security baseline – open API

Date: 2026-11-07

- `GET /recipes` → 200 OK, returns all recipes including `"is_public": false` items like `"Secret family hot sauce"`.
- `POST /recipes` → 201 CREATED, anonymous requester can create a new recipe (e.g. `"Anonymous test recipe"` with id 4).
- `DELETE /recipes/4` → 204 NO CONTENT, anonymous requester can delete an existing recipe; follow-up `GET /recipes` confirms id 4 is gone.