import requests
from flask import Blueprint

from api.utils import url_for, json_ok, json_error

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    url = url_for('threatLists')
    response = requests.get(url)

    if response.ok:
        return json_ok({'status': 'ok'})
    else:
        error = response.json()['error']
        return json_error(error)
