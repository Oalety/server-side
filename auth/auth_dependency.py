import json
import time
import urllib.request

from fastapi import HTTPException, Depends, Request, Header
from fastapi.security import OAuth2PasswordBearer, HTTPBearer
from jose import jwt, jwk
from jose.utils import base64url_decode

from core.config import settings
from schemas.auth import TokenData

#********************* AUTHENTICATION WITH BEARER TOKEN AWS COGNITO **********************

# Configuration for AWS Cognito
region = settings.REGION
userpool_id = settings.USER_POOL_ID
app_client_id = settings.CLIENT_ID
keys_url = f'https://cognito-idp.{region}.amazonaws.com/{userpool_id}/.well-known/jwks.json'

# Download JWKS on start
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

security = HTTPBearer()


def verify_token(token: str):
    """Verify the token using AWS official method."""
    # Get the header and kid from the JWT token
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    # Find the public key in the JWKS matching the kid
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break

    if key_index == -1:
        raise HTTPException(status_code=401, detail="Public key not found in jwks.json")

    # Construct the public key
    public_key = jwk.construct(keys[key_index])

    # Get message and signature from the token
    message, encoded_signature = str(token).rsplit('.', 1)

    # Decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # Verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        raise HTTPException(status_code=401, detail="Signature verification failed")

    # Get unverified claims
    claims = jwt.get_unverified_claims(token)

    # Verify expiration time
    if time.time() > claims['exp']:
        raise HTTPException(status_code=401, detail="Token is expired")

    # Check whether it's an ID token or access token
    token_use = claims.get("token_use")

    if token_use == "id":
        # ID Token - verify the `aud` claim
        if claims.get('aud') != app_client_id:
            raise HTTPException(status_code=401, detail="ID Token was not issued for this audience")

    elif token_use == "access":
        # Access Token - verify the `client_id` claim
        if claims.get('client_id') != app_client_id:
            raise HTTPException(status_code=401, detail="Access Token was not issued for this audience")

    else:
        # If token_use is neither 'id' nor 'access', it might be an invalid token
        raise HTTPException(status_code=401, detail="Invalid token type")

    return claims


async def get_current_user(request: Request, token: str = Depends(security), access_token: str | None = Header(default=None)):
    """Get current user by verifying the token."""
    id_token = token.credentials
    try:
        # Verify the token and extract claims
        claims = verify_token(id_token)

        # Get username or sub from claims
        username = claims.get('email') or claims.get('sub')  # Cognito ID tokens may use 'sub'
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token: username not found")

        return TokenData(username=username, id_token=id_token, access_token=access_token)

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
