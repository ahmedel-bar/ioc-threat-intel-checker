import logging
from app import create_app, socketio
from app import pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

app = create_app()

with app.app_context():
    pipeline.start(socketio)

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SIEM Threat Intelligence Platform")
    print("  http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
