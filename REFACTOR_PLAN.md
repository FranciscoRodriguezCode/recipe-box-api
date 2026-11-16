## Acceptance list (public API contract)

- POST /register
  - 201: returns a summary of the newly registered user, confirming account creation
  - 400: username, email, and password are required but missing
  - 409: a user with the same email/username already exists

- POST /login
  - 200: returns a JWT when email/password are correct
  - 400: missing required information
  - 401: invalid credentials

- GET /recipes
  - 200: returns a dictionary (JSON object) of recipes

- GET /recipes/<id>
  - 200: returns a dictionary (JSON object) for that recipe
  - 404: recipe not found

- POST /recipes
  - 201: successfully created recipe after passing JWT
  - 400: title and ingredients are required but missing/invalid
  - 401: invalid or missing token

- PATCH /recipes/<id>
  - 200: patch successful after passing JWT and ownership check
  - 400: data not entered correctly
  - 403: user not allowed to edit someone else’s recipe
  - 404: recipe not found

- DELETE /recipes/<id>
  - 204: No Content if successful with ownership + JWT check
  - 403: Forbidden if user not allowed to delete
  - 404: Not Found if recipe doesn’t exist