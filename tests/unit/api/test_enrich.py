from datetime import datetime
from http import HTTPStatus
from unittest import mock
from urllib.parse import quote

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def implemented_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=implemented_routes(),
         ids=lambda route: f'POST {route}')
def implemented_route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(implemented_route,
                                               client,
                                               invalid_json):
    response = client.post(implemented_route, json=invalid_json)

    # The actual error message is quite unwieldy, so let's just ignore it.
    expected_payload = {
        'errors': [
            {
                'code': 'invalid argument',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def gsb_api_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'


@fixture(scope='module',
         params=gsb_api_routes(),
         ids=lambda route: f'POST {route}')
def gsb_api_route(request):
    return request.param


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


def test_enrich_call_with_valid_json_but_invalid_jwt_failure(gsb_api_route,
                                                             client,
                                                             valid_json,
                                                             invalid_jwt):
    response = client.post(gsb_api_route,
                           json=valid_json,
                           headers=headers(invalid_jwt))

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


def all_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


@fixture(scope='function')
def gsb_api_request():
    with mock.patch('requests.post') as mock_request:
        yield mock_request


def gsb_api_response_ok():
    mock_response = mock.MagicMock()

    mock_response.ok = True

    payload = {
        'matches': [
            {
                'threatType': 'MALWARE',
                'platformType': 'WINDOWS',
                'threat': {'url': 'https://www.google.com/'},
                'cacheDuration': '400s',
                'threatEntryType': 'URL',
            },
            {
                'threatType': 'POTENTIALLY_HARMFUL_APPLICATION',
                'platformType': 'LINUX',
                'threat': {'url': 'https://www.google.com/'},
                'cacheDuration': '300s',
                'threatEntryType': 'URL',
            },
            {
                'threatType': 'SOCIAL_ENGINEERING',
                'platformType': 'CHROME',
                'threat': {'url': 'https://www.google.com/'},
                'cacheDuration': '200s',
                'threatEntryType': 'URL',
            },
            {
                'threatType': 'UNWANTED_SOFTWARE',
                'platformType': 'OSX',
                'threat': {'url': 'https://www.google.com/'},
                'cacheDuration': '100s',
                'threatEntryType': 'URL',
            },
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


@fixture(scope='module')
def unix_epoch_datetime():
    with mock.patch('api.enrich.datetime') as mock_datetime:
        mock_datetime.utcnow.return_value = datetime(1970, 1, 1)
        yield mock_datetime


@fixture(scope='module')
def expected_payload(any_route, client, unix_epoch_datetime):
    app = client.application

    payload = None

    if any_route.startswith('/deliberate'):
        observable = {'type': 'url', 'value': 'https://www.google.com/'}

        # Convert GSB threat types to TR dispositions.
        # Sort the corresponding GSB matches by
        # (TR disposition, GSB cache duration)
        # and choose the first one as a verdict.

        payload = {
            'verdicts': {
                'count': 1,
                'docs': [
                    {
                        'disposition': 2,
                        'disposition_name': 'Malicious',
                        'observable': observable,
                        'valid_time': {
                            'end_time': '1970-01-01T00:03:20Z',  # 200s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_VERDICT_DEFAULTS']
                    },
                ],
            },
        }

    if any_route.startswith('/observe'):
        observable = {'type': 'url', 'value': 'https://www.google.com/'}

        source_uri = app.config['GSB_TRANSPARENCY_REPORT_URL'].format(
            url=quote(observable['value'], safe=':')
        )

        # Implement a dummy class initializing its instances
        # only after the first comparison with any other object.
        class LazyEqualizer:
            NONE = object()

            def __init__(self):
                self.value = self.NONE

            def __eq__(self, other):
                if self.value is self.NONE:
                    self.value = other

                return self.value == other

        # Treat each GSB match as a TR judgement and
        # apply the same logic as in the previous case.

        judgement_ids = [LazyEqualizer() for _ in range(4)]

        payload = {
            'verdicts': {
                'count': 1,
                'docs': [
                    {
                        'disposition': 2,
                        'disposition_name': 'Malicious',
                        'judgement_id': judgement_ids[0],
                        'observable': observable,
                        'valid_time': {
                            'end_time': '1970-01-01T00:03:20Z',  # 200s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_VERDICT_DEFAULTS']
                    },
                ],
            },
            'judgements': {
                'count': 4,
                'docs': [
                    {
                        'disposition': 2,
                        'disposition_name': 'Malicious',
                        'id': judgement_ids[0],
                        'observable': observable,
                        'reason': 'SOCIAL_ENGINEERING : CHROME',
                        'severity': 'High',
                        'source_uri': source_uri,
                        'valid_time': {
                            'end_time': '1970-01-01T00:03:20Z',  # 200s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_JUDGEMENT_DEFAULTS']
                    },
                    {
                        'disposition': 2,
                        'disposition_name': 'Malicious',
                        'id': judgement_ids[1],
                        'observable': observable,
                        'reason': 'MALWARE : WINDOWS',
                        'severity': 'High',
                        'source_uri': source_uri,
                        'valid_time': {
                            'end_time': '1970-01-01T00:06:40Z',  # 400s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_JUDGEMENT_DEFAULTS']
                    },
                    {
                        'disposition': 3,
                        'disposition_name': 'Suspicious',
                        'id': judgement_ids[2],
                        'observable': observable,
                        'reason': 'UNWANTED_SOFTWARE : OSX',
                        'severity': 'Medium',
                        'source_uri': source_uri,
                        'valid_time': {
                            'end_time': '1970-01-01T00:01:40Z',  # 100s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_JUDGEMENT_DEFAULTS']
                    },
                    {
                        'disposition': 3,
                        'disposition_name': 'Suspicious',
                        'id': judgement_ids[3],
                        'observable': observable,
                        'reason': 'POTENTIALLY_HARMFUL_APPLICATION : LINUX',
                        'severity': 'Medium',
                        'source_uri': source_uri,
                        'valid_time': {
                            'end_time': '1970-01-01T00:05:00Z',  # 300s
                            'start_time': '1970-01-01T00:00:00Z',
                        },
                        **app.config['CTIM_JUDGEMENT_DEFAULTS']
                    },
                ],
            },
        }

    if any_route.startswith('/refer'):
        payload = [
            {
                'categories': ['Search', 'Google Safe Browsing'],
                'description': 'Check this domain status with '
                               'Google Safe Browsing',
                'id': 'ref-gsb-search-domain-cisco.com',
                'title': 'Search for this domain',
                'url': app.config['GSB_TRANSPARENCY_REPORT_URL'].format(
                    url='cisco.com'
                ),
            },
            {
                'categories': ['Search', 'Google Safe Browsing'],
                'description': 'Check this URL status with '
                               'Google Safe Browsing',
                'id': 'ref-gsb-search-url-https%3A%2F%2Fwww.google.com%2F',
                'title': 'Search for this URL',
                'url': app.config['GSB_TRANSPARENCY_REPORT_URL'].format(
                    url='https:%2F%2Fwww.google.com%2F'
                ),
            },
        ]

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             gsb_api_request,
                             valid_jwt,
                             expected_payload):
    app = client.application

    response = None

    if any_route.startswith(('/deliberate', '/observe')):
        gsb_api_request.return_value = gsb_api_response_ok()

        response = client.post(any_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        expected_url = app.config['GSB_API_URL'].format(
            endpoint='threatMatches:find',
            key=jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key'],
        )

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
        }

        gsb_api_request.assert_called_once_with(
            expected_url,
            json={
                'client': {
                    'clientId': app.config['GSB_API_CLIENT_ID'],
                    'clientVersion': app.config['GSB_API_CLIENT_VERSION'],
                },
                'threatInfo': {
                    'threatTypes': list(
                        app.config['GSB_API_THREAT_TYPES'].keys()
                    ),
                    'platformTypes': app.config['GSB_API_PLATFORM_TYPES'],
                    'threatEntryTypes': (
                        app.config['GSB_API_THREAT_ENTRY_TYPES']
                    ),
                    'threatEntries': [
                        {'url': 'cisco.com'},
                        {'url': 'https://www.google.com/'},
                    ],
                },
            },
            headers=expected_headers,
        )

    if any_route.startswith('/refer'):
        response = client.post(any_route, json=valid_json)

    assert response is not None, f'Unknown route: {any_route}.'

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_enrich_call_with_external_error_from_gsb_failure(gsb_api_route,
                                                          client,
                                                          valid_json,
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
            "and limit 'Lookup API requests per day' "
            "of service 'safebrowsing.googleapis.com' "
            "for consumer 'project_number:314159265358'.",
            'RESOURCE_EXHAUSTED',
        ),
    ]:
        app = client.application

        gsb_api_request.return_value = gsb_api_response_error(code,
                                                              message,
                                                              status)

        response = client.post(gsb_api_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        expected_url = app.config['GSB_API_URL'].format(
            endpoint='threatMatches:find',
            key=jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key'],
        )

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
        }

        gsb_api_request.assert_called_once_with(
            expected_url,
            json={
                'client': {
                    'clientId': app.config['GSB_API_CLIENT_ID'],
                    'clientVersion': app.config['GSB_API_CLIENT_VERSION'],
                },
                'threatInfo': {
                    'threatTypes': list(
                        app.config['GSB_API_THREAT_TYPES'].keys()
                    ),
                    'platformTypes': app.config['GSB_API_PLATFORM_TYPES'],
                    'threatEntryTypes': (
                        app.config['GSB_API_THREAT_ENTRY_TYPES']
                    ),
                    'threatEntries': [
                        {'url': 'cisco.com'},
                        {'url': 'https://www.google.com/'},
                    ],
                },
            },
            headers=expected_headers,
        )

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
