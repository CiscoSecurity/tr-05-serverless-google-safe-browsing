[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-google-safe-browsing.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-google-safe-browsing)

# Google Safe Browsing Relay API

A sample Relay API implementation using the
[Google Safe Browsing API](https://developers.google.com/safe-browsing/v4)
as an example of a third-party Threat Intelligence service provider.

The API itself is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Deployment

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Usage

```bash
export URL=<...>
export JWT=<...>

http POST "${URL}"/health Authorization:"Bearer ${JWT}"
http POST "${URL}"/deliberate/observables Authorization:"Bearer ${JWT}" < observables.json
http POST "${URL}"/observe/observables Authorization:"Bearer ${JWT}" < observables.json
http POST "${URL}"/refer/observables Authorization:"Bearer ${JWT}" < observables.json
```
