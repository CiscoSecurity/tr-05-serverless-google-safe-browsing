from http import HTTPStatus

import requests
from flask import Blueprint

from api.utils import url_for, execute, headers, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    url = url_for('threatLists')

    if url is None:
        # Mimic the GSB API error response payload.
        error = {
            'code': HTTPStatus.FORBIDDEN,
            'message': 'The request is missing a valid API key.',
            'status': 'PERMISSION_DENIED',
        }
        return jsonify_errors(error)

    _, error = execute(requests.get, url, headers=headers())

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
