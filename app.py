import os
import sqlite3
from functools import wraps

from flask import Flask, render_template, request, redirect, session, flash
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Create an empty database on first run, without distributing user data.
with sqlite3.connect("tasks.db") as connection:
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            completed INTEGER DEFAULT 0,
            due_date TEXT,
            priority INTEGER DEFAULT 0,
            category TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

# Connect to database
db = SQL("sqlite:///tasks.db")

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped_view

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        task = request.form.get("task", "").strip()
        if task:  # only insert if not empty
            db.execute("INSERT INTO tasks (task, user_id) VALUES (?, ?)", task[:200], session["user_id"])
        return redirect("/")

    # Get tasks for logged-in user
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", session["user_id"])
    return render_template("index.html", tasks=tasks)


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    task_id = request.form.get("id")
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", task_id, session["user_id"])
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate input
        if not username or not password or not confirmation:
            flash("Please fill out all fields")
            return render_template("register.html")
        if password != confirmation:
            flash("Passwords do not match")
            return render_template("register.html")
        if len(username) < 3 or len(username) > 40:
            flash("Username must be 3 to 40 characters")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters")
            return render_template("register.html")
        if db.execute("SELECT id FROM users WHERE username = ?", username):
            flash("Username already taken")
            return render_template("register.html")

        # Werkzeug hashes passwords before they are stored.
        hash_pw = generate_password_hash(password)

        user_id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pw)

        session["user_id"] = user_id
        return redirect("/")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")

        if not username or not password:
            flash("Must provide username and password")
            return render_template("login.html")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username or password")
            return render_template("login.html")

        session.clear()
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
