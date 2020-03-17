from typing import Optional

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify


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


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
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

    return jsonify({'errors': [error]})
