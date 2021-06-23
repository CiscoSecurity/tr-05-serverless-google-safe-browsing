import json
from json.decoder import JSONDecodeError
from ssl import SSLCertVerificationError
from typing import Optional

import jwt
import requests
from flask import request, current_app, jsonify
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from requests.exceptions import (
    SSLError, ConnectionError, InvalidURL, HTTPError)

from api.errors import AuthenticationRequiredError

NO_HEADER = 'Authorization header is missing'
WRONG_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def get_auth_token():
    expected_errors = {
        KeyError: NO_HEADER,
        AssertionError: WRONG_TYPE
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


def get_public_key(jwks_host, token):
    expected_errors = (
        ConnectionError,
        InvalidURL,
        JSONDecodeError,
        HTTPError
    )
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        response.raise_for_status()
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except expected_errors:
        raise AuthenticationRequiredError(WRONG_JWKS_HOST)


def get_key():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """
    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: WRONG_JWKS_HOST,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }

    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}).get('jwks_host')
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthenticationRequiredError(message)


def url_for(endpoint) -> Optional[str]:
    key = get_key()  # GSB_API_KEY

    if key is None:
        return None

    return current_app.config['GSB_API_URL'].format(
        endpoint=endpoint,
        key=key,
    )


def headers():
    return {
        'User-Agent': current_app.config['CTR_USER_AGENT'],
    }


def execute(method, *args, **kwargs):
    """Execute an HTTP method and return a (data, error) pair."""

    try:
        response = method(*args, **kwargs)
    except SSLError as error:
        # Go through a few layers of wrapped exceptions.
        error = error.args[0].reason.args[0]
        # Assume that a certificate could not be verified.
        assert isinstance(error, SSLCertVerificationError)
        reason = getattr(error, 'verify_message', error.args[0]).capitalize()
        # Mimic the GSB API error response payload.
        error = {
            'message': f'Unable to verify SSL certificate: {reason}.',
            'status': 'SSL_CERTIFICATE_VERIFICATION_FAILED',
        }
        return None, error

    if response.ok:
        return response.json(), None
    else:
        # The GSB API error response payload is already well formatted.
        return None, response.json()['error']


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error, data=None):
    # Make the actual GSB error payload compatible with the expected TR error
    # payload in order to fix the following types of possible UI alerts, e.g.:
    # :code (not (instance? java.lang.String 40x)),
    # :details disallowed-key,
    # :status disallowed-key,
    # etc.
    error['code'] = error.pop('status').lower().replace('_', ' ')
    error.pop('details', None)

    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    payload = {'errors': [error]}
    if data:
        payload['data'] = data

    current_app.logger.error(payload)

    return jsonify(payload)
