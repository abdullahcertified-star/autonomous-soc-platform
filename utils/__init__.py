"""SOC utility package. Root `utils.py` is shadowed when this package exists — ``ts`` lives here."""
from datetime import datetime


def ts() -> str:
    return datetime.now().strftime("%I:%M:%S %p")
