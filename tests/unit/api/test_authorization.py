from http import HTTPStatus

from pytest import fixture
from requests.exceptions import ConnectionError, InvalidURL

from .utils import headers
from api.errors import AuthenticationRequiredError
from tests.unit.api.mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)
from api.utils import (
    NO_HEADER,
    WRONG_TYPE,
    WRONG_JWKS_HOST,
    WRONG_PAYLOAD_STRUCTURE,
    JWK_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)

CODE = AuthenticationRequiredError.CODE
MESSAGE = AuthenticationRequiredError.MESSAGE


def gsb_api_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/health'


@fixture(scope='module',
         params=gsb_api_routes(),
         ids=lambda route: f'POST {route}')
def gsb_api_route(request):
    return request.param


@fixture(scope='module')
def authorization_errors_expected_payload():
    def _make_payload_message(message):
        payload = {
            'errors': [{
                'code': CODE,
                'message': f'{MESSAGE}: {message}',
                'type': 'fatal'
            }]
        }
        return payload

    return _make_payload_message


def test_call_with_authorization_header_failure(
        gsb_api_route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(gsb_api_route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(NO_HEADER)


def test_call_with_wrong_auth_type(
        gsb_api_route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt(), type_='not')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(WRONG_TYPE)


def test_call_with_wrong_jwks_host(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        gsb_api_request_get.side_effect = error()

        response = client.post(
            gsb_api_route, json=valid_json, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


def test_call_with_wrong_jwt_payload_structure(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt(wrong_structure=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE
    )


def test_call_with_missing_jwks_host(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt(jwks_host=''))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWK_HOST_MISSING
    )


def test_call_with_wrong_key(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt())
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )


def test_call_with_wrong_jwt_structure(
        gsb_api_route, client, valid_json, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers('valid_jwt()')
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


def test_call_with_wrong_audience(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt(aud='wrong_audience'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


def test_call_with_wrong_kid(
        gsb_api_route, client, valid_json, valid_jwt, gsb_api_request_get,
        rsa_api_response, authorization_errors_expected_payload
):
    gsb_api_request_get.return_value = rsa_api_response(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        gsb_api_route, json=valid_json,
        headers=headers(valid_jwt(kid='wrong_kid'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        KID_NOT_FOUND
    )
