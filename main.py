# from flask import Flask, render_template
import os
from dotenv import load_dotenv
import sqlite3
from pathlib import Path
from functools import wraps

from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    session, 
    flash, 
    g
    )

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import(
    generate_password_hash,
    check_password_hash
)
# Flask application

load_dotenv()

app = Flask(__name__)


secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

CSRFProtect(app)

# 2. SQLite database location

DB_PATH = Path(app.instance_path) / "users.db"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def get_db():
    if "db" not in g:
        # connect to SQLite
        g.db = sqlite3.connect(DB_PATH) 
        g.db.row_factory = sqlite3.Row
    return g.db

# Close database connection

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)

    if db is not None:
        db.close()

# 5. Create users table

def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    db.commit()


with app.app_context():
    init_db()

# homepage 
@app.route("/")
def home():
    return render_template("index.html")

# signup
@app.route("/signup" , method = ["GET","POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not email or "@" not in email:
            flash("Enter a valid name and vaild email" , "error")

        elif len(password)<8:
            flash("Password character must have at least 8 characters" , "error")

        elif password != confirm:
            flash("Password do not match", "error")

        else:
            hashed_password = generate_password_hash(password)

            try:
                db = get_db()

                db.execute("""    INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)""",
                    (name,email,hashed_password))
                db.commit

            except sqlite3.IntegrityError:
                get_db().rollback()
                flash("Email already registered.", "error")

            else:
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login")
def login():
    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Invalid email or password.", "error")

        else:
            session.clear()
            session["user_id"] = user["id"]

            db.execute(
                """
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (user["id"],)
            )

            db.commit()

            return redirect(url_for("dashboard"))

    return render_template("login.html")


# 9. Protect private pages

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)

# Logout
@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("You have logged out successfully.", "success")

    return redirect(url_for("login"))

# 12. Run Flask locally

if __name__ == "__main__":
    app.run(debug=True)
