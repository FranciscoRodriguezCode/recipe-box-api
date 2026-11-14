"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
from functools import wraps
from flask import Flask, g, jsonify, request, current_app
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "recipes.db"
load_dotenv()
JWT_SECRET = os.environ.get("JWT_SECRET")
app = Flask(__name__)


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header with Bearer token required"}), 401

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        user_id = payload.get("sub")
        user_role = payload.get("role")
        if user_id is None:
            return jsonify({"error": "invalid token"}), 401

        g.current_user_id = user_id
        g.current_user_role = user_role

        return fn(*args, **kwargs)
    return wrapper


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
        "owner_id": row["owner_id"],
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))



@app.post("/recipes")
def create_recipe():
    # 1) Read Authorization header
    auth_header = request.headers.get("Authorization", "")

    # 2) Require Bearer format
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header with Bearer token required"}), 401

    # 3) Extract the raw token string
    token = auth_header.split(" ", 1)[1].strip()

    # 4) VERIFY the token signature and extract identity
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
        )
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")
    if user_id is None:
        return jsonify({"error": "invalid token"}), 401

    # (we're not using user_id yet for ownership, just proving identity)
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,  # from the verified token
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    db = get_db()

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    user_id = g.current_user_id
    user_role = g.current_user_role

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid token"}), 401

    is_owner = (row["owner_id"] == user_id)
    is_admin = (user_role == "admin")

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden"}), 403

    values.append(recipe_id)
    try:
        db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 200

@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    db = get_db()

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # Make sure we compare ints to ints
    user_id = int(g.current_user_id)

    is_owner = (row["owner_id"] == user_id)
    is_admin = (g.current_user_role == "admin")

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden"}), 403

    db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    return "", 204

@app.post("/register")
def register():
    data = request.get_json(silent=True)
    
    #1. Basic validation
    if (
        not data
        or not data.get("username")
        or not data.get("email")
        or not data.get("password")
    ):
        return jsonify({"error": "username, email, and password are required"}), 400
        
    db = get_db()
    
    # 2. Hash the password
    password_hash = generate_password_hash(data["password"])
    
    try:
        # 3. Insert user with parametrized query
        cur = db.execute(
            """
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, datetime('now'))
            """,
            (data["username"], data["email"], password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # 4. Duplicate username or email
        return jsonify({"error": "username or email already exists"}), 409
        
    row = db.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?", (cur.lastrowid,),).fetchone()
        
    return (
        jsonify({
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "created_at": row["created_at"],
            }
        ),
        201,
    )

@app.post("/login")
def login():
    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return {"error": "username and passwords are required"}, 400

    db = get_db()
    cursor = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),
    )

    user = cursor.fetchone()

    # Generic 401 response (same for unknown user or wrong password)
    invalid_response = ({"error": "invalid credentials"}, 401)

    if user is None:
        return invalid_response

    if not check_password_hash(user["password_hash"], password):
        return invalid_response

    payload = {
    "sub": str(user["id"]),  # subject must be a string
    "role": user["role"],
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")   
    return {
        "id": user["id"],
        "username": user["username"],
        "token": token,
    }, 200
    
if __name__ == "__main__":
    app.run(debug=True)
