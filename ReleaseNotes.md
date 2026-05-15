<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA Tiger Testsuite

## Version: 1.0.1

Release date: 2026-05-12

Tiger Testsuite 1.0.1

This version is a maintenance release of the ZETA Testsuite.
It updates and extends the test coverage and stabilizes the build, documentation, runtime evidence, TLS checks, schema validation, and performance test handling.

#### Test Focus:

- Improved runtime coverage and partial failure reporting
- Updated schema validation and schema fixtures
- Hardened TLS test handling
- Refactored performance test execution
- Updated UseCase and scenario references
- Additional negative scenarios for client authentication, authorization, resource access, and refresh-token handling
- Stable CI and documentation build updates

### Known issues:

- Some tests require Kubernetes access to the target namespace and a matching ZETA Guard deployment configuration.
- Telemetry scenarios depend on the availability and current data retention of OpenSearch, Jaeger, Prometheus, and the Telemetrie-Gateway Collector configuration.

## Version: 1.0.0

Release date: 2026-05-04

> **BITTE BEACHTEN**
> Der Testplan referenziert die Spezifikation und Testaspekte, die im Repository enthalten sind.
> Die konkrete Ausführbarkeit einzelner Tests hängt weiterhin von der bereitgestellten ZETA Guard Testumgebung und deren Konfiguration ab.

Tiger Testsuite 1.0.0

This version is the first 1.0.0 release of the ZETA Testsuite.
It validates the ZETA protocol between the ZETA client SDK and the ZETA Guard, including happy-flow coverage, negative checks, telemetry validation, TLS checks, and performance-oriented scenarios.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation and validation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets
- PoPP Token Validation
- Policy Decision
- Telemetrie
- TLS Tests
- Performance Tests
- Runtime and configuration checks for selected Kubernetes-based ZETA Guard components

### Known issues:

- Some tests require Kubernetes access to the target namespace and a matching ZETA Guard deployment configuration.
- Telemetry scenarios depend on the availability and current data retention of OpenSearch, Jaeger, Prometheus, and the Telemetrie-Gateway Collector configuration.

#### Limitations

## Version: 0.5.0

> **BITTE BEACHTEN**
> Der Testplan referenziert die Vorabveröffentlichung der Spezifikation vom 16.03.2026.
> Er referenziert nicht den aktuellen Status der Implementierung der Testaspekte bzgl. der neuen oder
> geänderten Anforderungen.

Tiger Testsuite 0.5.0
TestProxy 0.5.0
TestFachdienst 0.5.0
zeta-tls-test-tool-service 0.5.0

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets
- PoPP Token Validation
- Policy Decision
- Telemetrie
- TLS Tests
- Performance Tests

### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefore some tests may fail as false negative.

#### Limitations

## Version: 0.4.0

Tiger Testsuite 0.4.0
TestProxy 0.4.0
TestFachdienst 0.4.0

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets (broken)
- PoPP Token Validation
- Policy Decision
- Telemetrie

### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefore many tests fail most of the time.

#### Limitations

## Version: 0.3.0

Tiger Testsuite 0.3.0
TestProxy 0.3.0
TestFachdienst 0.3.0

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets (broken)
- PoPP Token Validation
- Policy Decision
- Telemetrie

### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefore many tests fail most of the time.
- Tiger Local Proxy does not support Websockets, therefore the websocket tests fail.

#### Limitations


## Version: 0.2.5

Tiger Testsuite 0.2.5
TestProxy 0.2.5
TestFachdienst 0.2.1
ExAuthSim 0.2.1

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets (broken)
- PoPP Token Validation
- Policy Decision
- Telemetrie

### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefor many tests fail most of the time.
- Tiger Local Proxy does not support Websockets, therefore the websocket tests fail.

#### Limitations


## Version: 0.2.4

Tiger Testsuite 0.2.4
TestProxy 0.2.1
TestFachdienst 0.2.1
ExAuthSim 0.2.1

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets (broken)
- PoPP Token Validation
- Policy Decision


### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefor many tests fail most of the time.
- Tiger Local Proxy does not support Websockets, therefore the websocket tests fail.

#### Limitations

- Telemetrie


## Release 0.2.2

This version tests the "happy flow" for the ZETA protocol between the ZETA client SDK and the ZETA Guard.

Therefore, the stable API of the ZETA client SDK, the ZETA-Guard and the network protocol is tested (with comments see below).
Not all validations are tested yet and will follow in later releases.

#### Test Focus:

- Discovery of server parameters via .well-known files
- Nonce Endpoint
- Software-based Client Attestation
- DPoP token generation
- Client Registration
- SM(C)-B Token use
- Client Assertion
- Access Token handling
- Web Sockets (broken)


### Known issues:

- Tiger Testsuite and Standalone Tiger Proxy (TestProxy) communication is unreliable, therefor many tests fail most of the time.
- Tiger Local Proxy does not support Websockets, tehrefore the websocket tests fail.

#### Limitations

- PoPP Token Validation
- Policy Decision


## Release 0.1.3

### added:
- Prototype of the ZETA Tiger Testsuite