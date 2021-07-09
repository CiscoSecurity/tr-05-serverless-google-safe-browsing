from http import HTTPStatus
from itertools import product
from unittest import mock
from unittest.mock import call

from pytest import fixture

from .utils import headers
from api.utils import get_key
from tests.unit.api.mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def gsb_api_response_ok(app):
    mock_response = mock.MagicMock()

    mock_response.ok = True

    payload = {
        'threatLists': [
            {
                'threatType': threat_type,
                'platformType': platform_type,
                'threatEntryType': threat_entry_type,
            }
            for threat_type, platform_type, threat_entry_type in product(
                app.config['GSB_API_THREAT_TYPES'],
                app.config['GSB_API_PLATFORM_TYPES'],
                app.config['GSB_API_THREAT_ENTRY_TYPES'],
            )
        ]
    }

    mock_response.json = lambda: payload

    return mock_response


def gsb_api_response_error(code, message, status):
    mock_response = mock.MagicMock()

    mock_response.ok = False

    payload = {
        'error': {
            'code': code,
            'message': message,
            'status': status,
        }
    }

    mock_response.json = lambda: payload

    return mock_response


def test_health_call_success(route, client, rsa_api_response,
                             gsb_api_request_get, valid_jwt):
    app = client.application

    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(route, headers=headers(valid_jwt()))

    expected_url = app.config['GSB_API_URL'].format(
        endpoint='threatLists',
        key=get_key()
    )

    expected_headers = {
        'User-Agent': app.config['CTR_USER_AGENT'],
    }

    calls = [
        call('https://visibility.amp.cisco.com/.well-known/jwks'),
        call().raise_for_status(),
        call(expected_url, headers=expected_headers),
        call().ok.__bool__(),
        call('https://visibility.amp.cisco.com/.well-known/jwks'),
        call().raise_for_status()
    ]

    gsb_api_request_get.assert_has_calls(calls)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_external_error_from_gsb_failure(route,
                                                          client,
                                                          gsb_api_request_get,
                                                          valid_jwt,
                                                          rsa_api_response):
    for code, message, status in [
        (
                HTTPStatus.BAD_REQUEST,
                'API key not valid. Please pass a valid API key.',
                'INVALID_ARGUMENT',
        ),
        (
                HTTPStatus.TOO_MANY_REQUESTS,
                "Quota exceeded for quota group 'LookupAPIGroup' "
                "and limit 'Lookup API requests per 100 seconds' "
                "of service 'safebrowsing.googleapis.com' "
                "for consumer 'project_number:314159265358'.",
                'RESOURCE_EXHAUSTED',
        ),
    ]:
        app = client.application

        gsb_api_request_get.side_effect = (
            rsa_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
            gsb_api_response_error(code, message, status),
            rsa_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
        )

        response = client.post(route, headers=headers(valid_jwt()))

        expected_url = app.config['GSB_API_URL'].format(
            endpoint='threatLists',
            key=get_key()
        )

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
        }

        calls = [
            call('https://visibility.amp.cisco.com/.well-known/jwks'),
            call(expected_url, headers=expected_headers),
            call('https://visibility.amp.cisco.com/.well-known/jwks')
        ]

        gsb_api_request_get.assert_has_calls(calls)

        gsb_api_request_get.reset_mock()

        code = status.lower().replace('_', ' ')

        expected_payload = {
            'errors': [
                {
                    'code': code,
                    'message': message,
                    'type': 'fatal',
                }
            ]
        }

        assert response.status_code == HTTPStatus.OK
        assert response.get_json() == expected_payload
