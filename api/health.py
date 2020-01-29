import requests
from flask import Blueprint

from api.utils import url_for, jsonify_data, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    url = url_for('threatLists')
    response = requests.get(url)

    if response.ok:
        return jsonify_data({'status': 'ok'})
    else:
        error = response.json()['error']
        return jsonify_errors(error)
