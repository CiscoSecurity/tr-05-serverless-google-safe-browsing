import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    CTR_USER_AGENT = (
        'SecureX Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }

    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'schema_version': '1.0.17',
        'source': 'Google Safe Browsing',
        'confidence': 'High',
        'priority': 90,
        'tlp': 'white',
    }

    # GSB only works with URLs (domains are also acceptable),
    # so all the other types of observables have to be filtered out.
    GSB_OBSERVABLE_TYPES = {
        'url': 'URL',
        'domain': 'domain',
    }

    GSB_API_URL = 'https://safebrowsing.googleapis.com/v4/{endpoint}?key={key}'

    GSB_TRANSPARENCY_REPORT_URL = (
        'https://transparencyreport.google.com/safe-browsing/search?url={url}'
    )

    # https://developers.google.com/safe-browsing/v4/reference/rest/v4/ClientInfo
    GSB_API_CLIENT_ID = 'tr-google-safe-browsing-relay'
    GSB_API_CLIENT_VERSION = VERSION

    # https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
    GSB_API_THREAT_TYPES = {
        'MALWARE': (2, 'Malicious', 'High'),
        'SOCIAL_ENGINEERING': (2, 'Malicious', 'High'),
        'POTENTIALLY_HARMFUL_APPLICATION': (3, 'Suspicious', 'Medium'),
        'UNWANTED_SOFTWARE': (3, 'Suspicious', 'Medium'),
    }

    # https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
    GSB_API_PLATFORM_TYPES = [
        'WINDOWS',
        'LINUX',
        'ANDROID',
        'OSX',
        'IOS',
        'CHROME',
    ]

    # https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatEntryType
    GSB_API_THREAT_ENTRY_TYPES = ['URL']

    # https://developers.google.com/safe-browsing/v4/usage-limits#UsageRestrictions
    GSB_API_MAX_THREAT_ENTRIES_PER_REQUEST = 500
