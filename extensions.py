"""
Flask Extensions — initialized here to avoid circular imports.

All extensions are instantiated without an app object so they can be
imported safely by any module before create_app() runs.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db           = SQLAlchemy()
login_manager = LoginManager()

# WebSocket support — async_mode='threading' is compatible with the
# existing daemon threads started in create_app().
socketio = SocketIO(
    async_mode="threading",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)

# Global API rate limiter — 300 req/min per IP by default.
# Individual blueprints can override with tighter limits.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute", "3000 per hour"],
    storage_uri="memory://",
)
