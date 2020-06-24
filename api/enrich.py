import json
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import chain
from urllib.parse import quote
from uuid import uuid4

import requests
from flask import Blueprint, request, current_app

from api.bundle import Bundle
from api.schemas import ObservableSchema
from api.utils import url_for, headers, jsonify_data, jsonify_errors

enrich_api = Blueprint('enrich', __name__)


observables_schema = ObservableSchema(many=True)


def validate_relay_input():
    relay_input = request.get_json(force=True, silent=True, cache=False)

    error = observables_schema.validate(relay_input) or None
    if error:
        relay_input = None
        # Mimic the GSB API error response payload.
        error = {
            'code': 400,
            'message': f'Invalid JSON payload received. {json.dumps(error)}.',
            'details': error,
            'status': 'INVALID_ARGUMENT',
        }

    return relay_input, error


def group_observables(relay_input):
    # Leave only unique (value, type) pairs grouped by value.

    observables = defaultdict(set)

    for observable in relay_input:
        value = observable['value']
        type = observable['type'].lower()

        # Discard any unsupported type.
        if type in current_app.config['GSB_OBSERVABLE_TYPES']:
            observables[value].add(type)

    observables = {
        value: sorted(types)
        for value, types in observables.items()
    }

    return observables


def chunks(iterable, size):
    assert size > 0

    chunk = []

    for item in iterable:
        chunk.append(item)

        if len(chunk) == size:
            yield chunk
            chunk = []

    if chunk:
        yield chunk


def build_gsb_input(observables):
    return {
        'client': {
            'clientId': current_app.config['GSB_API_CLIENT_ID'],
            'clientVersion': current_app.config['GSB_API_CLIENT_VERSION'],
        },
        'threatInfo': {
            'threatTypes': list(
                current_app.config['GSB_API_THREAT_TYPES'].keys()
            ),
            'platformTypes': current_app.config['GSB_API_PLATFORM_TYPES'],
            'threatEntryTypes': (
                current_app.config['GSB_API_THREAT_ENTRY_TYPES']
            ),
            'threatEntries': [
                {'url': value} for value in observables.keys()
            ],
        },
    }


def validate_gsb_output(gsb_input):
    url = url_for('threatMatches:find')

    if url is None:
        # Mimic the GSB API error response payload.
        error = {
            'code': 403,
            'message': 'The request is missing a valid API key.',
            'status': 'PERMISSION_DENIED',
        }
        return None, error

    response = requests.post(url, json=gsb_input, headers=headers())

    if response.ok:
        return response.json(), None
    else:
        return None, response.json()['error']


def group_matches(gsb_output):
    matches = defaultdict(list)

    for match in gsb_output.get('matches', []):
        matches[match['threat']['url']].append(match)

    return matches


def key(match):
    # Usage:
    # 1. Convert GSB threat types to TR dispositions.
    # 2. Sort by TR disposition + GSB cache duration (optional).

    disposition, disposition_name, severity = (
        current_app.config['GSB_API_THREAT_TYPES'][match['threatType']]
    )

    # Format: 123.45s
    cache_duration = float(match['cacheDuration'][:-1])

    return disposition, cache_duration, disposition_name, severity


def extract_verdicts(observables, matches, start_time):
    docs = []

    for value, types in observables.items():
        if value not in matches:
            continue

        # Choose the first match as a verdict.
        verdict = sorted(matches[value], key=key)[0]

        disposition, cache_duration, disposition_name, _ = key(verdict)

        end_time = start_time + timedelta(seconds=cache_duration)

        valid_time = {
            'start_time': start_time.isoformat() + 'Z',
            'end_time': end_time.isoformat() + 'Z',
        }

        for type in types:
            observable = {'value': value, 'type': type}

            doc = {
                'observable': observable,
                'disposition': disposition,
                'disposition_name': disposition_name,
                'valid_time': valid_time,
                **current_app.config['CTIM_VERDICT_DEFAULTS']
            }

            if 'judgement_id' in verdict:
                # Link the verdict to a judgement (if specified).
                doc['judgement_id'] = verdict['judgement_id']

            docs.append(doc)

    return docs


def extract_judgements(observables, matches, start_time):
    docs = []

    for value, types in observables.items():
        if value not in matches:
            continue

        source_uri = current_app.config['GSB_TRANSPARENCY_REPORT_URL'].format(
            url=quote(value, safe=':')
        )

        judgements = sorted(matches[value], key=key)

        for judgement in judgements:
            disposition, cache_duration, disposition_name, severity = (
                key(judgement)
            )

            end_time = start_time + timedelta(seconds=cache_duration)

            valid_time = {
                'start_time': start_time.isoformat() + 'Z',
                'end_time': end_time.isoformat() + 'Z',
            }

            reason = f'{judgement["threatType"]} : {judgement["platformType"]}'

            for type in types:
                observable = {'value': value, 'type': type}

                judgement_id = f'transient:judgement-{uuid4()}'
                # Label each match with some "judgement_id".
                judgement['judgement_id'] = judgement_id

                doc = {
                    'id': judgement_id,
                    'observable': observable,
                    'disposition': disposition,
                    'disposition_name': disposition_name,
                    'severity': severity,
                    'valid_time': valid_time,
                    'reason': reason,
                    'source_uri': source_uri,
                    **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
                }

                docs.append(doc)

    return docs


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input, error = validate_relay_input()

    if error:
        return jsonify_errors(error)

    observables = group_observables(relay_input)

    if not observables:
        # Optimize a bit by not sending empty requests to the GSB API.
        return jsonify_data({})

    bundle = Bundle()

    start_time = datetime.utcnow()

    # Split the data into chunks and make multiple requests to the GSB API.

    size = current_app.config['GSB_API_MAX_THREAT_ENTRIES_PER_REQUEST']

    for observables in map(dict, chunks(observables.items(), size)):
        gsb_input = build_gsb_input(observables)

        gsb_output, error = validate_gsb_output(gsb_input)

        if error:
            return jsonify_errors(error, data=bundle.json())

        matches = group_matches(gsb_output)

        verdicts = extract_verdicts(observables, matches, start_time)

        for entity in verdicts:
            bundle.add(entity)

    relay_output = bundle.json()

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input, error = validate_relay_input()

    if error:
        return jsonify_errors(error)

    observables = group_observables(relay_input)

    if not observables:
        # Optimize a bit by not sending empty requests to the GSB API.
        return jsonify_data({})

    bundle = Bundle()

    start_time = datetime.utcnow()

    # Split the data into chunks and make multiple requests to the GSB API.

    size = current_app.config['GSB_API_MAX_THREAT_ENTRIES_PER_REQUEST']

    for observables in map(dict, chunks(observables.items(), size)):
        gsb_input = build_gsb_input(observables)

        gsb_output, error = validate_gsb_output(gsb_input)

        if error:
            return jsonify_errors(error, data=bundle.json())

        matches = group_matches(gsb_output)

        # Extract judgements first in order to label each match with some
        # "judgement_id", so that it can be extracted for each verdict later.
        judgements = extract_judgements(observables, matches, start_time)
        verdicts = extract_verdicts(observables, matches, start_time)

        for entity in chain(judgements, verdicts):
            bundle.add(entity)

    relay_output = bundle.json()

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    relay_input, error = validate_relay_input()

    if error:
        return jsonify_errors(error)

    observables = group_observables(relay_input)

    relay_output = [
        {
            'id': f'ref-gsb-search-{type}-{quote(value, safe="")}',
            'title': (
                'Search for this '
                f'{current_app.config["GSB_OBSERVABLE_TYPES"][type]}'
            ),
            'description': (
                'Check this '
                f'{current_app.config["GSB_OBSERVABLE_TYPES"][type]} '
                'status with Google Safe Browsing'
            ),
            'url': (
                current_app.config['GSB_TRANSPARENCY_REPORT_URL'].format(
                    url=quote(value, safe=':')
                )
            ),
            'categories': ['Search', 'Google Safe Browsing'],
        }
        for value, types in observables.items()
        for type in types
    ]

    return jsonify_data(relay_output)
