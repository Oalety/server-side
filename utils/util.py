import base64
import hashlib
import hmac

from core.config import settings


def generate_secret_hash(username: str, client_id: str = settings.CLIENT_ID, client_secret: str = settings.CLIENT_SECRET) -> str:
    message = username + client_id
    dig = hmac.new(
        key=client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()