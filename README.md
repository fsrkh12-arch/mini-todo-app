# To-Do List

A small Flask application for keeping a personal task list. It was built to explore how a web interface, user accounts, and a database fit together.

## Try it

[Open the browser demo](https://fsrkh12-arch.github.io/mini-todo-app/)

The demo runs entirely in your browser. Its account and task data stay in that browser; it does not connect to the Flask application or sync between devices. Use sample credentials rather than a password you use elsewhere.

## Flask application

The Python version lets users register, sign in, add tasks, and delete their own tasks. It uses Flask and Jinja for the web interface, SQLite through the CS50 library for storage, and Werkzeug to hash passwords. The repository currently includes the SQLite database used by the application.

To run it locally, install Python, then from the repository directory run:

```sh
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app run
```

Open the local address printed by Flask. For deployment, configure a private `SECRET_KEY`; the default generates a new key when the process starts. This is a learning project, not a security-audited production service.
