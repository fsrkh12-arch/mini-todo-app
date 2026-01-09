from flask import Flask, render_template, request, redirect, session, flash
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "replace_with_a_random_secret_key"  # needed to keep all the sessions in track

# Connect to database
db = SQL("sqlite:///tasks.db")

@app.route("/", methods=["GET", "POST"])
def index():
    # User must be logged in
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        task = request.form.get("task")
        if task:  # only insert if not empty
            db.execute("INSERT INTO tasks (task, user_id) VALUES (?, ?)", task, session["user_id"])
        return redirect("/")

    # Get tasks for logged-in user
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", session["user_id"])
    return render_template("index.html", tasks=tasks)


@app.route("/delete", methods=["POST"])
def delete():
    task_id = request.form.get("id")
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", task_id, session["user_id"])
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate input
        if not username or not password or not confirmation:
            flash("Please fill out all fields")
            return render_template("register.html")
        if password != confirmation:
            flash("Passwords do not match")
            return render_template("register.html")

        # Hash password
        hash_pw = generate_password_hash(password)

        # Insert into DB
        try:
            user_id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pw)
        except:
            flash("Username already taken")
            return render_template("register.html")

        session["user_id"] = user_id
        return redirect("/")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()  # forget any previous user

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Must provide username and password")
            return render_template("login.html")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username or password")
            return render_template("login.html")

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
