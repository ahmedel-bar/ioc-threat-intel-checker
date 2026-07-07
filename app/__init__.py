import logging
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from app.config import Config
from app import database as db

logger = logging.getLogger(__name__)
socketio = SocketIO()


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["SECRET_KEY"] = Config.SECRET_KEY

    if Config.SECRET_KEY == "dev-secret-key":
        logger.warning(
            "\n" + "!" * 70 +
            "\n  [SECURITY] Default SECRET_KEY in use."
            "\n  Set SECRET_KEY=<random-string> in your .env before deployment." +
            "\n" + "!" * 70
        )

    CORS(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    db.init_db()

    if Config.EMULATION_ENABLED:
        from app.emulation.schema import init_emulation_schema
        init_emulation_schema()
        if Config.EMULATION_SEED_ON_BOOT:
            from app.emulation.loader import seed_from_disk
            counts = seed_from_disk()
            logger.info("[EMULATION] Seeded %d actors, %d plans from disk", counts["actors"], counts["plans"])

    from app.routes import bp
    app.register_blueprint(bp)

    return app
