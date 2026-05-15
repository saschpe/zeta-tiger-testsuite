#
# #%L
# ZETA Testsuite
# %%
# (C) achelos GmbH, 2025, licensed for gematik GmbH
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
# #L%
#

#language:de

@UseCase_01_07
Funktionalität: client_authentisierung_und_autorisierung_software_attest_sc_400

  @A_25767
  @A_26661
  @A_27007
  @A_28963
  @TA_A_25767_02
  @TA_A_26661_02
  @TA_A_27007_02
  @TA_A_28963_01
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenariogrundriss: DPoP JWT Manipulation Test - Token Request - 1
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"

    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"

    # Manipulation wird neu signiert, damit die geänderten Felder validiert werden.
    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "<JwtField>" auf Wert "<NeuerWert>" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Vorladen der Nachrichten, damit die nachfolgende Suche nach dem manipulierten Wert schneller durchläuft
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"

    # Finde den manipulierten Request anhand des geänderten Wertes
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.root}.<JwtField>" der mit "<NeuerWert>" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

    # iat in der Vergangenheit (2023-12-01)
    # iat in der Zukunft (2050-01-01)
    Beispiele: Manipulationen
      | JwtField   | NeuerWert               |
      | header.typ | JWT                     |
      | body.nonce | 1234567                 |
      | header.alg | HS256                   |
      | header.alg | RS999                   |
      | body.iat   | 1701432000              |
      | body.iat   | 2524608000              |
      | body.htm   | GET                     |
      | body.htu   | https://wrong.url/token |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft einen DPoP Proof mit Header-Algorithmus none am Token-Endpunkt
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalTokenRequestDpopJwt"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Und erzeuge aus "${originalTokenRequestDpopJwt}" ein DPoP JWT mit Header-Algorithmus none und speichere in Variable "manipulatedDpopJwt"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${manipulatedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft einen DPoP Proof mit fremdem JWK und unveränderter Signatur am Token-Endpunkt
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.jwk.x}" der aktuellen Anfrage in der Variable "foreignTokenRequestDpopJwkX"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "header.jwk.x" auf Wert "${foreignTokenRequestDpopJwkX}" für Pfad "${pathCondition}" und 1 Ausführungen
    Und TGR lösche aufgezeichnete Nachrichten

    # Nach reset verwendet der Client ein neues DPoP Keypair; der eingesetzte fremde JWK-Anteil passt damit nicht mehr zur Signatur.
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.header.jwk.x}" der mit "${foreignTokenRequestDpopJwkX}" übereinstimmt
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "manipulatedTokenRequestDpopJwt"
    Und prüfe die JWT-Variante "invalid_signature" in "${manipulatedTokenRequestDpopJwt}" hat lokal die erwartete Signaturintegrität
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenariogrundriss: ZETA Guard verwirft einen DPoP Proof ohne Pflicht-Claim am Token-Endpunkt
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalTokenRequestDpopJwt"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Und erzeuge aus "${originalTokenRequestDpopJwt}" ein DPoP JWT ohne Claim "<Claim>" mit privatem Schlüssel "${dpopKey}" und speichere in Variable "manipulatedDpopJwt"
    Und verifiziere ES256 Signatur von DPoP JWT "${manipulatedDpopJwt}"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${manipulatedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

    Beispiele: Fehlende Pflicht-Claims
      | Claim |
      | jti   |
      | htm   |
      | htu   |
      | iat   |

  # TODO: Bei Bedarf später nach erwarteten ResponseCodes aufsplitten und in passende UseCases verteilen.
  @A_25767
  @A_26661
  @A_27007
  @A_28963
  @TA_A_25767_02
  @TA_A_26661_02
  @TA_A_27007_02
  @TA_A_28963_01
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenariogrundriss: DPoP JWT Manipulation Test - Token Request - 2
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Hole einen Private Key über storage (wird für Signatur und JWK-Ersetzung verwendet)
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"

    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"

    # Manipulation mit JWK-Ersetzung - Signatur ist gültig, aber JWK ist von anderem Key
    # Der ZETA Guard prüft typ/nonce bevor er das JWK-Binding validiert
    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "<JwtField>" auf Wert "<NeuerWert>" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Vorladen der Nachrichten, damit die nachfolgende Suche nach dem manipulierten Wert schneller durchläuft
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"

    # Finde den manipulierten Request anhand des geänderten Wertes
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.root}.<JwtField>" der mit "<NeuerWert>" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

    # iat in der Vergangenheit (2023-12-01)
    # iat in der Zukunft (2050-01-01)
    Beispiele: Manipulationen
      | JwtField   | NeuerWert               |
      | header.typ | JWD                     |
      | header.alg | RS256                   |
      | body.nonce | invalidNonceValue123    |
      | body.iat   | 1701432000              |
      | body.iat   | 2524608000              |
      | body.htm   | DELETE                  |
      | body.htu   | https://wrong.url/token |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenariogrundriss: ZETA Guard verwirft einen nicht wohlgeformten DPoP Proof am Token-Endpunkt (<Variante>)
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # initialer Request, um ein DPoP als Vorlage zu generieren
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalTokenRequestDpopJwt"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Und erzeuge die JWT-Variante "<Variante>" aus "${originalTokenRequestDpopJwt}" mit privatem Schlüssel "${dpopKey}" und speichere in Variable "malformedDpopJwt"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${malformedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.root}" überein mit "${malformedDpopJwt}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

    Beispiele: manipulierte JWT-Varianten
      | Variante                           |
      | invalid_header_json_unquoted_keys  |
      | invalid_payload_json_unquoted_keys |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft doppelte DPoP Header am Token-Endpunkt
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Dann TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Und Dupliziere im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und prüfe aktuelle Anfrage enthält den Header "DPoP" 2 mal
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft einen DPoP Proof mit privatem JWK Anteil am Token-Endpunkt
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "header.jwk.d" auf Wert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.header.jwk.d}" der mit "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft am Token-Endpunkt die Wiederverwendung desselben jti
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"
    Und erzeuge eindeutige DPoP jti und speichere in Variable "tokenReplayJti"
    Und TGR setze lokale Variable "accessTokenTtl" auf "1"
    Und TGR setze lokale Variable "refreshTokenTtl" auf "60"
    Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 1 Ausführungen
    Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 1 Ausführungen

    Und Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "body.jti" auf Wert "${tokenReplayJti}" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 2 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.body.jti}" der mit "${tokenReplayJti}" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.jti}" überein mit "${tokenReplayJti}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    Und warte "2" Sekunden
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.body.jti}" der mit "${tokenReplayJti}" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.jti}" überein mit "${tokenReplayJti}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  # TODO: Dieser Szenariogrundriss bündelt Varianten mit unterschiedlichen erwarteten Statuscodes.
  # Eine spätere Aufteilung nach Zielstatuscode und passendem UseCase sollte geprüft werden.
  @A_27802-02
  @TA_A_27802-02_01
  @TA_A_27802-02_02
  @MASVS-CRYPTO
  Szenariogrundriss: ZETA Guard verwirft fehlerhafte Client Assertion JWT Varianten
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    Und TGR setze lokale Variable "tokenRequestCondition" auf ".*${paths.guard.tokenEndpointPath}"

    # RFC 7519, Abschnitt 7.2:
    # - Punkt-separierte JWT-Serialisierung
    # - base64url-decodierbarer und JSON-parsbarer Header
    # - JWS/JWE-Unterscheidung und verschachteltes JWT via cty=JWT
    # - base64url-decodierbare und interpretierbare Claims-Menge
    #
    # RFC 7515, Abschnitt 5.2:
    # - decodierbare JWS-Segmente
    # - doppelte / unbekannte / kritische Header-Parameter
    # - vorhandenes und akzeptables alg
    # - Signaturprüfung über den Signing Input
    Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "variant.name" auf Wert "<Variante>" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${tokenRequestCondition}" und 1 Ausführungen und ersetze JWK

    Und TGR lösche aufgezeichnete Nachrichten
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "MANIPULATED_CLIENT_ASSERTION"
    Und prüfe die JWT-Variante "<Variante>" in "${MANIPULATED_CLIENT_ASSERTION}" hat lokal die erwartete Signaturintegrität
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "<ResponseCode>"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.error_description"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.error_description" nicht überein mit ".*client_id parameter does not match sub claim.*"

    Beispiele: JWT und JWS Fehlervarianten
      | Variante                     | ResponseCode |
      | two_segments                 | 400          |
      | invalid_header_base64url     | 400          |
      | invalid_header_json          | 400          |
      | jwe_like_five_segments       | 400          |
      | nested_cty_jwt_invalid_inner | 400          |
      | invalid_payload_base64url    | 400          |
      | invalid_payload_json         | 400          |
      | unknown_header_parameter     | 400          |
      | invalid_signature_base64url  | 400          |
      | unsupported_crit             | 400          |
      | unsupported_alg              | 400          |
      | duplicate_alg_headers        | 400          |
      | missing_alg                  | 400          |
      | invalid_signature            | 401          |

  # TODO: Dieser Szenariogrundriss bündelt Varianten mit unterschiedlichen erwarteten Statuscodes.
  # Eine spätere Aufteilung nach Zielstatuscode und passendem UseCase sollte geprüft werden.
  @A_27802-02
  @TA_A_27802-02_01
  @TA_A_27802-02_02
  @dev
  @MASVS-CRYPTO
  Szenariogrundriss: Client Assertion JWT Manipulation Test - Token Request
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # Löse Generieren des Client Key aus
    Und TGR sende eine leere GET Anfrage an "${paths.client.discover}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.register}"

    # Hole den Client Private Key über storage (wird für Signatur und JWK-Ersetzung verwendet)
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR gebe aktuelle Response als Rbel-Tree aus

    Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.tokenEndpointPath}"

    Dann Setze im TigerProxy für JWT in "<JwtLocation>" das Feld "<JwtField>" auf Wert "<NeuerWert>" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Vorladen der Nachrichten, damit die nachfolgende Suche nach dem manipulierten Wert schneller durchläuft
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"

    # Finde den manipulierten Request anhand des geänderten Wertes
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "<JwtLocation>.<JwtField>" der mit "<NeuerWert>" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "<ResponseCode>"

    # A_27802-02 - ZETA Guard, JWT Prüfung
    # - Header:
    # -- Algorithmus (alg)
    # - Payload:
    # -- Ablaufdatum (exp) => 401 bei abgelaufenem JWT (gemSpec_ZETA#Tabelle_12)
    # -- Audience (aud)
    # -- Issuer (iss)
    # -- Integrität: Hash-Prüfung
    # -- Schlüsselvalidierung
    Beispiele: Manipulationen
      | JwtLocation             | JwtField   | NeuerWert               | ResponseCode |
      | $.body.client_assertion | header.typ | helloWorld              | 400          |
      | $.body.client_assertion | header.alg | RS999                   | 400          |
      | $.body.client_assertion | body.exp   | 1763370594              | 401          |
      | $.body.client_assertion | body.aud.0 | https://wrong.url/token | 400          |

  # US2 @A_25649
  # US2 @TA_A_25649_01
  # US2 @dev
  # US2 Szenario: Neue Session ohne neue Attestation (Negativtest)
  # US2   # TTL-Werte als Variablen definieren (in Sekunden)
  # US2   Wenn TGR setze lokale Variable "accessTokenTtl" auf "30"
  # US2   Und TGR setze lokale Variable "refreshTokenTtl" auf "100"
  # US2   # kleinen Puffer addieren, um Timing-Rennen zu vermeiden
  # US2   Und TGR setze lokale Variable "refreshTokenWait" auf "!{${refreshTokenTtl} + 2}"

  # US2   # OPA Decision manipulieren: Kurze TTL für Refresh Token setzen
  # US2   # Die OPA-Response bestimmt die tatsächliche Token-Gültigkeit im Authorization Server
  # US2   Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
  # US2   Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 3 Ausführungen
  # US2   Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 3 Ausführungen

  # US2   # Client zurücksetzen und ersten Token holen
  # US2   Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
  # US2   Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

  # US2   # Warten dass HelloZeta-Response vollständig geparst ist
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"


  # US2   # Ersten Token Request validieren
  # US2   Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
  # US2   Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"

  # US2   # session_expiry = expiry vom ersten refresh_token
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token.body.exp"
  # US2   Und TGR speichere Wert des Knotens "$.body.refresh_token.body.exp" der aktuellen Antwort in der Variable "session_expiry"

  # US2   # Entferne client_statement aus der Client Assertion für die nächste Token-Exchange-Anfrage
  # US2   Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
  # US2   Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
  # US2   Und TGR setze lokale Variable "pathCondition" auf "message.path =~ '.*${paths.guard.tokenEndpointPath}' && message.body.grant_type =~ '.*token-exchange'"
  # US2   Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "body.client_statement" auf Wert "{}" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK

  # US2   # Warte bis das Refresh Token und damit session_expiry abgelaufen ist
  # US2   Und warte "${refreshTokenWait}" Sekunden
  # US2   Und validiere, dass der Zeitstempel "${session_expiry}" in der Vergangenheit liegt

  # US2   # Nachrichten löschen für die finale Phase
  # US2   Und TGR lösche aufgezeichnete Nachrichten

  # US2   # Zweite Anfrage sollte neue Authentisierung auslösen (weil RT abgelaufen)
  # US2   Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

  # US2   # Warten dass HelloZeta-Response vollständig geparst ist
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"


  # US2   # TA_A_25662_03: Nachweis 2: Token Request verwendet grant_type=token-exchange (nicht refresh_token)
  # US2   # Bei abgelaufenem RT muss der Client eine neue Authentisierung durchführen (Token Exchange)
  # US2   # Hinweis: grant_type ist URL-encoded, da der Request Body application/x-www-form-urlencoded ist
  # US2   Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" übereinstimmt
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
  # US2   Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
  # US2   Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  # US2   # TA_A_25649_01: Neue Session erfordert Client-Attestierung, aber client_statement wurde entfernt
  # US2   Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
  # US2   Und TGR prüfe aktueller Request enthält nicht Knoten "$.body.client_assertion.body.client_statement.attestation_timestamp"
  # US2   Und TGR prüfe aktueller Request enthält nicht Knoten "$.body.client_assertion.body.client_statement.posture"


  # US2 @A_25644-01
  # US2 @TA_A_25644-01_03
  # US2 @MASVS-AUTH
  # US2 @tpm_environment
  # US2 Szenario: TPM Attestation - ungültige Quote wird abgelehnt (Negativtest)
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.discover}"
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.register}"

    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    # US2 Und TGR setze lokale Variable "pathCondition" auf "message.path =~ '.*${paths.guard.tokenEndpointPath}' && message.body.grant_type =~ '.*token-exchange'"

    # US2 Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "body.client_statement.posture.tpm_quote" auf Wert "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK
    # US2 Und TGR lösche aufgezeichnete Nachrichten

    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # US2 Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.client_assertion.body.client_statement.posture.tpm_quote" der mit "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" übereinstimmt
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    # US2 Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    # US2 Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"


  # US2 @A_25644-01
  # US2 @TA_A_25644-01_05
  # US2 @dev
  # US2 @MASVS-AUTH
  # US2 Szenario: Plattformwechsel nach Ablauf des Refresh Tokens wird abgelehnt (Negativtest)
    # US2 # TTL-Werte als Variablen definieren (in Sekunden)
    # US2 Wenn TGR setze lokale Variable "accessTokenTtl" auf "5"
    # US2 Und TGR setze lokale Variable "refreshTokenTtl" auf "15"

    # US2 # OPA Decision manipulieren: Kurze TTL für Refresh Token setzen
    # US2 # Die OPA-Response bestimmt die tatsächliche Token-Gültigkeit im Authorization Server
    # US2 Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    # US2 Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 1 Ausführungen
    # US2 Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 1 Ausführungen

    # US2 # Client zurücksetzen und ersten Token holen
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # US2 Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # US2 # Ersten Token Request validieren
    # US2 Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.platform" überein mit "linux"

    # US2 # session_expiry = expiry vom ersten refresh_token
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token.body.exp"
    # US2 Und TGR speichere Wert des Knotens "$.body.refresh_token.body.exp" der aktuellen Antwort in der Variable "session_expiry"

    # US2 # Warte bis das Refresh Token und damit session_expiry abgelaufen ist
    # US2 Und warte "${refreshTokenTtl}" Sekunden
    # US2 Und validiere, dass der Zeitstempel "${session_expiry}" in der Vergangenheit liegt

    # US2 # Nachrichten löschen für die finale Phase
    # US2 Und TGR lösche aufgezeichnete Nachrichten

    # US2 # Hole den Client Private Key über storage (wird für Signatur und JWK-Ersetzung verwendet)
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    # US2 Und TGR setze lokale Variable "pathCondition" auf "message.path =~ '.*${paths.guard.tokenEndpointPath}' && message.body.grant_type =~ '.*token-exchange'"

    # US2 Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "body.client_statement.platform" auf Wert "windows" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK

    # US2 # Zweite Anfrage sollte neue Authentisierung auslösen (weil RT abgelaufen)
    # US2 Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # US2 Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.client_assertion.body.client_statement.platform" der mit "windows" übereinstimmt
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    # US2 Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    # US2 Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
