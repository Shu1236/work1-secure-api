"""Entry point.

Development:  python app.py            (or: flask --app app run)
Production:   gunicorn "app:app"       (never app.run() behind a proxy)
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

from secure_api import create_app

load_dotenv()

app = create_app()

# ``flask --app app run`` and gunicorn both look for a module-level object.
application = app


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    # debug stays off: the Werkzeug debugger is an RCE console.
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
