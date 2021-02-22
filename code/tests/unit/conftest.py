from unittest import mock

import jwt
from pytest import fixture

from app import app
from tests.unit.api.mock_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='function')
def gsb_api_request_get():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='function')
def gsb_api_request_post():
    with mock.patch('requests.post') as mock_request:
        yield mock_request


@fixture(scope='function')
def rsa_api_response():
    def _make_mock(payload):
        mock_response = mock.MagicMock()
        mock_response.json = lambda: payload
        return mock_response

    return _make_mock


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='In Google Safe Browsing we trust!',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            limit=100,
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'domain',
            'value': 'cisco.com',
        },
        {
            'type': 'url',
            'value': 'https://www.google.com/',
        },
        {
            'type': 'ip',
            'value': '8.8.8.8',
        },
        {
            'type': 'sha256',
            'value': '01' * 32,
        },
        {
            'type': 'file_name',
            'value': 'danger.exe',
        },
    ]
