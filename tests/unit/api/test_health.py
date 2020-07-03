from http import HTTPStatus
from itertools import product
from unittest import mock

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))

    expected_payload = {
        'errors': [
            {
                'code': 'permission denied',
                'message': 'The request is missing a valid API key.',
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@fixture(scope='function')
def gsb_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


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


def test_health_call_success(route, client, gsb_api_request, valid_jwt):
    app = client.application

    gsb_api_request.return_value = gsb_api_response_ok(app)

    response = client.post(route, headers=headers(valid_jwt))

    expected_url = app.config['GSB_API_URL'].format(
        endpoint='threatLists',
        key=jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key'],
    )

    expected_headers = {
        'User-Agent': app.config['CTR_USER_AGENT'],
    }

    gsb_api_request.assert_called_once_with(expected_url,
                                            headers=expected_headers)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_external_error_from_gsb_failure(route,
                                                          client,
                                                          gsb_api_request,
                                                          valid_jwt):
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

        gsb_api_request.return_value = gsb_api_response_error(code,
                                                              message,
                                                              status)

        response = client.post(route, headers=headers(valid_jwt))

        expected_url = app.config['GSB_API_URL'].format(
            endpoint='threatLists',
            key=jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key'],
        )

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
        }

        gsb_api_request.assert_called_once_with(expected_url,
                                                headers=expected_headers)

        gsb_api_request.reset_mock()

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
