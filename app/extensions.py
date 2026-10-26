"""Flask extension instances, created unbound and initialised in the factory."""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

# Keyed on remote address. Behind a reverse proxy, ProxyFix is applied in the
# factory so that X-Forwarded-For is honoured instead of the proxy's own IP.
limiter = Limiter(key_func=get_remote_address)
