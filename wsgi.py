"""
WSGI entry point.

Development:
    flask --app wsgi run
Production (Gunicorn, Linux):
    gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app
Production (Waitress, Windows):
    waitress-serve --listen=127.0.0.1:8000 wsgi:app
"""

import os

from dotenv import load_dotenv

# Load .env before the configuration object reads the environment.
load_dotenv()

from app import create_app  # noqa: E402  (import must follow load_dotenv)

app = create_app(os.environ.get("FLASK_CONFIG", "development"))


if __name__ == "__main__":
    # debug is driven by configuration, not hard-coded, so that a production
    # run can never accidentally expose the Werkzeug debugger.
    app.run(
        host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_RUN_PORT", 5000)),
        debug=app.config.get("DEBUG", False),
    )
