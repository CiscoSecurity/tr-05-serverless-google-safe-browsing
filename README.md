[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# NOTE! This code has been upgraded and the current release no longer supports installation in AWS
If you wish to deploy in AWS, use [this](https://github.com/CiscoSecurity/tr-05-serverless-google-safe-browsing/releases/tag/v1.2.1) previous release.

# Google Safe Browsing Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using
[Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/overview)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

## Rationale
- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](code/requirements.txt) file:
```
pip install --upgrade --requirement code/requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:
  `cd code`
  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](code/observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-google-safe-browsing .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-google-safe-browsing tr-05-google-safe-browsing
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-google-safe-browsing
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /deliberate/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Verdict`.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Judgement`,
    - `Verdict`.

- `POST /refer/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Builds a search link per each supported observable to pivot back to the
  underlying external service and look up the observable there.
  - Returns a list of those links.

- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `url`
- `domain`

### CTIM Mapping Specifics

GSB stores its data split into so-called Safe Browsing Lists (SBLs). The SBLs
are Google's constantly updated lists of unsafe web resources. Examples of
unsafe web resources are social engineering sites (phishing and deceptive
sites) and sites that host malware or unwanted software. Each SBL is named
(identified) using three parameters or type combinations: the `ThreatType`,
`PlatformType`, and `ThreatEntryType`. Since the `ThreatEntryType` is limited
to `URL` for this particular integration, the SBLs are actually represented
using the corresponding `ThreatType`/`PlatformType` pairs.

Available `ThreatType`s:
- `MALWARE`
- `SOCIAL_ENGINEERING`
- `UNWANTED_SOFTWARE`
- `POTENTIALLY_HARMFUL_APPLICATION`

Available `PlatformType`s:
- `WINDOWS`
- `LINUX`
- `ANDROID`
- `OSX`
- `IOS`
- `CHROME`

Each GSB threat match (i.e. occurrence of a URL in an SBL) results in a CTIM
`Judgement`. The `reason` of the `Judgement` contains both the `ThreatType` and
`PlatformType` of the SBL. The `valid_time:start_time` of the `Judgement` is
set to the current time and the `valid_time:end_time` of the `Judgement` is set
to the `valid_time:start_time` plus the recommended cache duration (e.g. `300s`)
also provided by GSB for each threat match. The `disposition_name` and
`severity` of the `Judgement` depend on the `ThreatType` of the SBL:
- `MALWARE` or `SOCIAL_ENGINEERING` – `Malicious` and `High` respectively;
- `UNWANTED_SOFTWARE` or `POTENTIALLY_HARMFUL_APPLICATION` – `Suspicious` and
`Medium` respectively.

A CTIM `Verdict` for a URL can be derived from a `Judgement` selected from the
URL's `Judgement`s according to the simple rules listed below:
1. Take the `Judgement` with the highest disposition (`Malicious` >
`Suspicious`).
2. If there are several `Judgement`s of this kind, take the one with the
shortest `valid_time` (i.e. the shortest cache duration).
3. If there are several `Judgement`s of this kind, take any one of them (e.g.
the first one in the order they were returned by GSB).
