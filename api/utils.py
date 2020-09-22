from ssl import SSLCertVerificationError
from typing import Optional

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from requests.exceptions import SSLError


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def url_for(endpoint) -> Optional[str]:
    key = get_jwt().get('key')  # GSB_API_KEY

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
    # Avoiding of circular imports
    from app import app

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

    app.logger.error(payload)

    return jsonify(payload)
