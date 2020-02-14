import requests
from flask import Blueprint

from api.utils import url_for, jsonify_data, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    url = url_for('threatLists')

    if url is None:
        # Mimic the GSB API error response payload.
        error = {
            'code': 403,
            'message': 'The request is missing a valid API key.',
            'status': 'PERMISSION_DENIED',
        }
        return jsonify_errors(error)

    response = requests.get(url)

    if response.ok:
        return jsonify_data({'status': 'ok'})
    else:
        error = response.json()['error']
        return jsonify_errors(error)
