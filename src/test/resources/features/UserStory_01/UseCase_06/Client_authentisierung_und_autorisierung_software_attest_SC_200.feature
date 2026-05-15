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

@UseCase_01_06
Funktionalität: Client_authentisierung_und_autorisierung_software_attest_SC_200

  @A_26639
  @TA_A_26639_01
  @critical
  @no_proxy
  @websocket
  @MASVS-NETWORK
  Szenario: Ingress unterstützt WebSocket Verbindung
    Wenn eine WebSocket Verbindung zu "${paths.client.websocketBaseUrl}" geöffnet wird
    Dann wird die WebSocket Verbindung geschlossen

  @A_28432
  @TA_A_28432_01
  @require_kubectl
  @MASVS-NETWORK
  Szenario: Ingress ist vorhanden und wird für den Client-Pfad verwendet
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und ermittle aus den Pods im Namespace "${zetaDeploymentConfig.namespace}" den Wert aus der Spalte "IP" der Zeile mit "ingress" und speichere in der Variable "INGRESS_IP"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body"
    Und TGR prüfe aktueller Request enthält Knoten "$.sender.domain"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.sender.domain" überein mit "${INGRESS_IP}"

  @A_28144
  @TA_A_28144_01
  @TA_A_28144_02
  @TA_A_28144_03
  @MASVS-CRYPTO
  Szenariogrundriss: Nonce am Endpunkt GET /nonce
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "<request_url>"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "NONCE"
    Und decodiere Base64Url "${NONCE}" und prüfe, dass die Länge 128 bit ist

    @trivial
    Beispiele: Integration
      | request_url               |
      | ${paths.client.helloZeta} |

    @no_proxy
    Beispiele: Komponententest
      | request_url                                            |
      | ${paths.guard.baseUrl}${paths.guard.nonceEndpointPath} |

  @A_28144
  @TA_A_28144_04
  @MASVS-CRYPTO
  Szenariogrundriss: Nonce ist zufällig
    # erste nonce
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "<request_url>"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "NONCE"
    # zweite nonce
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "<request_url>"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body" nicht überein mit "${NONCE}"

    Beispiele: Integration
      | request_url               |
      | ${paths.client.helloZeta} |

    @no_proxy
    Beispiele: Komponententest
      | request_url                                            |
      | ${paths.guard.baseUrl}${paths.guard.nonceEndpointPath} |


  @A_25660
  @A_25661
  @A_25760
  @A_26281-01
  @A_26661
  @A_26944
  @A_27007
  @TA_A_25660_01
  @TA_A_25660_04
  @TA_A_25661_01
  @TA_A_25661_02
  @TA_A_25760_03
  @TA_A_26281-01_01
  @TA_A_26661_01
  @TA_A_26944_01
  @TA_A_27007_01
  @dev
  @MASVS-AUTH
  @MASVS-CRYPTO
  Szenario: Die Komponente Authorization Server MUSS Access Token mit Attributen gemäß [access-token.yaml] und Refresh Token ausstellen (Integrationstest)
    Gegeben sei TGR sende eine leere "GET" Anfrage an "${paths.guard.baseUrl}${paths.guard.certsEndpointPath}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.certsEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "KEY_STORE"

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body.access_token" der aktuellen Antwort in der Variable "JWT_TOKEN"
    Und TGR speichere Wert des Knotens "$.body.refresh_token" der aktuellen Antwort in der Variable "REFRESH_TOKEN"
    Und decodiere und validiere "${JWT_TOKEN}" gegen Schema "schemas/v_1_0/access-token.yaml"
    Und verifiziere die ES256 Signatur des JWT "${JWT_TOKEN}" mit KeyStore "${KEY_STORE}"

    # TA_A_25660_04, TA_A_25760_03, TA_A_25661_02 - Refresh Token muss vorhanden sein
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token"
    Und verifiziere die ES256 Signatur des JWT "${REFRESH_TOKEN}" mit KeyStore "${KEY_STORE}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

  @A_25661
  @A_25739-02
  @A_26585-01
  @A_27401
  @A_28527
  @A_28837
  @TA_A_25661_01
  @TA_A_25661_02
  @TA_A_25739-02_01
  @TA_A_26585-01_02
  @TA_A_27401_01
  @TA_A_28527_01
  @TA_A_28527_02
  @TA_A_28837_01
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: Policy Decision - Token Ausgabe mit korrekter Laufzeit gemäß OPA
    # TTL Werte als Variablen definieren
    Gegeben sei TGR setze lokale Variable "accessTokenTtl" auf "60"
    Und TGR setze lokale Variable "refreshTokenTtl" auf "120"

    # OPA Response manipulieren: TTL Werte setzen
    # Die manipulierte OPA-Response bestimmt die tatsächliche Token-Gültigkeit im Authorization Server.
    Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 1 Ausführungen
    Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 1 Ausführungen

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.registerEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.client_id" der aktuellen Antwort in der Variable "CLIENT_ID"

    # TA_A_28837_01: Nach dem Token-Exchange-Request muss vor der Token-Ausgabe eine Policy-Engine-Anfrage erfolgen.
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" übereinstimmt
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"

    Dann TGR finde die nächste Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body.input" der aktuellen Anfrage in der Variable "POLICY_ENGINE_INPUT"
    Und validiere "${POLICY_ENGINE_INPUT}" gegen Schema "schemas/v_1_0/policy-engine-input.yaml"

    # TA_A_26585-02_02: Client-Daten werden gemäß policy-engine-client-data.yaml an die Policy Engine weitergegeben
    Und TGR prüfe aktueller Request enthält Knoten "$.body.input.client_registration_data"
    Und TGR speichere Wert des Knotens "$.body.input.client_registration_data" der aktuellen Anfrage in der Variable "CLIENT_DATA"
    Und validiere "${CLIENT_DATA}" gegen Schema "schemas/v_1_0/policy-engine-client-data.yaml"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.input.client_registration_data.client_id"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.client_registration_data.client_id" überein mit "${CLIENT_ID}"

    # TA_A_27401_01: OPA Response Schema-Validierung
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "PDP_DECISION"
    Und validiere "${PDP_DECISION}" gegen Schema "schemas/v_1_0/pdp-decision.yaml"

    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result.allow"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result.ttl"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result.ttl.access_token"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result.ttl.refresh_token"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.result.ttl.access_token" überein mit "${accessTokenTtl}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.result.ttl.refresh_token" überein mit "${refreshTokenTtl}"

    # TA_A_25739-02_01: Aktive OPA Instanz trifft Entscheidung
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.result.allow" überein mit "true"

    # Token Response prüfen: Das ausgegebene Token-Set muss die zuvor gelieferte Policy-Engine-Decision berücksichtigen.
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # TA_A_25661_01: Access Token wird bei allow=true ausgegeben
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.access_token"

    # TA_A_25661_02: Refresh Token wird bei allow=true ausgegeben
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token"

    # TA_A_28527_01: Access Token Laufzeit gemäß Policy Engine
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.expires_in" überein mit "${accessTokenTtl}"
    # Tiger parst JWTs automatisch - prüfe TTL über exp - iat Differenz im JWT
    Und TGR speichere Wert des Knotens "$.body.access_token.body.exp" der aktuellen Antwort in der Variable "accessExp"
    Und TGR speichere Wert des Knotens "$.body.access_token.body.iat" der aktuellen Antwort in der Variable "accessIat"
    Und prüfe dass Token TTL zwischen exp="${accessExp}" und iat="${accessIat}" gleich "${accessTokenTtl}" Sekunden ist

    # TA_A_28527_02: Refresh Token Laufzeit gemäß Policy Engine
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.refresh_expires_in" überein mit "${refreshTokenTtl}"
    # Tiger parst JWTs automatisch - prüfe TTL über exp - iat Differenz im JWT
    Und TGR speichere Wert des Knotens "$.body.refresh_token.body.exp" der aktuellen Antwort in der Variable "refreshExp"
    Und TGR speichere Wert des Knotens "$.body.refresh_token.body.iat" der aktuellen Antwort in der Variable "refreshIat"
    Und prüfe dass Token TTL zwischen exp="${refreshExp}" und iat="${refreshIat}" gleich "${refreshTokenTtl}" Sekunden ist

  @A_28440
  @TA_A_28440_01
  @dev
  @MASVS-AUTH
  Szenario: Client-IP Adresse wird aus Forwarded-Header übernommen
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.discover}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.register}"

    Gegeben sei TGR setze lokale Variable "clientIp" auf "198.51.100.60"
    Und TGR setze lokale Variable "forwardedHeader" auf "for=${clientIp}"
    Und TGR setze lokale Variable "forwardedCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    # Hinweis: A_28828: "Forwarded" ist bevorzugt, aber "X-Forwarded-For" und "X-Real-IP" sind ebenfalls zulässig, deshalb werden alle drei Header manipuliert
    Und Setze im TigerProxy für die Nachricht "${forwardedCondition}" die Manipulation auf Feld "${headers.forwarded.strict}" und Wert "${forwardedHeader}"
    Und Setze im TigerProxy für die Nachricht "${forwardedCondition}" die Manipulation auf Feld "${headers.xForwardedFor}" und Wert "${clientIp}"
    Und Setze im TigerProxy für die Nachricht "${forwardedCondition}" die Manipulation auf Feld "${headers.xRealIp}" und Wert "${clientIp}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR warte auf eine Nachricht, in der Knoten "$.path" mit "${paths.guard.helloZetaPath}" übereinstimmt

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.input.authorization_request.ip_address"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.authorization_request.ip_address" überein mit "${clientIp}"


  # US2 @A_25649
  @A_25662
  # US2 @TA_A_25649_01
  @TA_A_25662_03
  @dev
  @MASVS-AUTH
  Szenario: Neue Authentisierung nach Ablauf der Refresh Token Gültigkeitsdauer
    # TTL-Werte als Variablen definieren (in Sekunden)
    Wenn TGR setze lokale Variable "accessTokenTtl" auf "30"
    Und TGR setze lokale Variable "refreshTokenTtl" auf "100"
    # kleinen Puffer addieren, um Timing-Rennen zu vermeiden
    Und TGR setze lokale Variable "refreshTokenWait" auf "!{${refreshTokenTtl} + 2}"

    # OPA Decision manipulieren: Kurze TTL für Refresh Token setzen
    # Die OPA-Response bestimmt die tatsächliche Token-Gültigkeit im Authorization Server
    Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 3 Ausführungen
    Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 3 Ausführungen

    # Client zurücksetzen und ersten Token holen
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Warten dass HelloZeta-Response vollständig geparst ist
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # Merke die Nonce für später
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "firstNonce"

    # Ersten Token Request validieren
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"

    # session_expiry = expiry vom ersten refresh_token
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token.body.exp"
    Und TGR speichere Wert des Knotens "$.body.refresh_token.body.exp" der aktuellen Antwort in der Variable "session_expiry"
    # sessionId speichern, um später neue Session nachzuweisen
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token.body.sid"
    Und TGR speichere Wert des Knotens "$.body.access_token.body.sid" der aktuellen Antwort in der Variable "sessionId"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.refresh_token.body.sid" überein mit "${sessionId}"

    # US2 # Speichere attestationTimestamp und attestationChallenge zum späteren Vergleich
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.attestation_timestamp"
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture.attestation_challenge"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.attestation_timestamp" der aktuellen Anfrage in der Variable "attestationTimestamp1"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture.attestation_challenge" der aktuellen Anfrage in der Variable "attestationChallenge1"

    # Warte bis das Refresh Token und damit session_expiry abgelaufen ist
    Und warte "${refreshTokenWait}" Sekunden
    Und validiere, dass der Zeitstempel "${session_expiry}" in der Vergangenheit liegt

    # Nachrichten löschen für die finale Phase
    Und TGR lösche aufgezeichnete Nachrichten

    # Zweite Anfrage sollte neue Authentisierung auslösen (weil RT abgelaufen)
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Warten dass HelloZeta-Response vollständig geparst ist
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # TA_A_25662_03: Validiere dass neue Authentisierung erfolgt
    # Nachweis 1: Neuer Nonce Request wurde durchgeführt
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # Prüfe dass ein NEUER Nonce ausgegeben wurde
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body" nicht überein mit "${firstNonce}"

    # TA_A_25662_03: Nachweis 2: Token Request verwendet grant_type=token-exchange (nicht refresh_token)
    # Bei abgelaufenem RT muss der Client eine neue Authentisierung durchführen (Token Exchange)
    # Hinweis: grant_type ist URL-encoded, da der Request Body application/x-www-form-urlencoded ist
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # Session ID stimmt nicht überein mit der alten Session ID
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.refresh_token.body.sid" nicht überein mit "${sessionId}"

    # US2 # TA_A_25649_01: Neue Session erfordert Client-Attestierung
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.attestation_timestamp"
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture.attestation_challenge"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.attestation_timestamp" der aktuellen Anfrage in der Variable "attestationTimestamp2"
    # US2 Und validiere, dass der Zeitstempel "${attestationTimestamp2}" später als "${attestationTimestamp1}" liegt
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.attestation_challenge" nicht überein mit "${attestationChallenge1}"

  @A_25663
  @A_25766
  @A_25767
  @A_28963
  @TA_A_25663_01
  @TA_A_25766_02
  @TA_A_25767_02
  @TA_A_28963_01
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: DPoP Token Request - Client sendet DPoP Header und erhält DPoP-gebundenen Access Token
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "tokenNonce"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"

    # Token Response Validierung
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.token_type" überein mit "DPoP"

    # DPoP JWT Validierung
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "dpopJwt"
    Und decodiere und validiere "${dpopJwt}" gegen Schema "schemas/v_1_0/dpop-token.yaml"
    Und verifiziere ES256 Signatur von DPoP JWT "${dpopJwt}"
    Und berechne JKT aus DPoP JWT "${dpopJwt}" und speichere in Variable "dpopJwtJkt"
    # @TA_A_25663_01 - Token Binding: cnf.jkt muss mit DPoP Public Key Thumbprint übereinstimmen
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.access_token.body.cnf.jkt" überein mit "${dpopJwtJkt}"

    # DPoP Header Validierung
    # @TA_A_28963_01 - typ muss "dpop+jwt" sein
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.typ}" überein mit "dpop+jwt"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.alg}" überein mit "ES256"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.kty}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.jwk.kty}" überein mit "EC"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.jwk.crv}" überein mit "P-256"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.jwk.x}" der aktuellen Anfrage in der Variable "dpopJwkX"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.jwk.y}" der aktuellen Anfrage in der Variable "dpopJwkY"
    Und decodiere Base64Url "${dpopJwkX}" und prüfe, dass die Länge 256 bit ist
    Und decodiere Base64Url "${dpopJwkY}" und prüfe, dass die Länge 256 bit ist
    Und TGR speichere Wert des Knotens "${headers.dpop.header.root}" der aktuellen Anfrage in der Variable "dpopHeader"
    Und prüfe dass jwk in "${dpopHeader}" keine privaten Key-Teile enthält

    # DPoP Payload Validierung
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.jti}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htm}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htu.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.iat}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htm}" überein mit "POST"
    Und TGR speichere Wert des Knotens "${headers.xForwardedProto}" der aktuellen Anfrage in der Variable "requestScheme"
    Und TGR speichere Wert des Knotens "${headers.xForwardedHost}" der aktuellen Anfrage in der Variable "requestHost"
    Und TGR ersetze ":443$" mit "" im Inhalt der Variable "requestHost"
    Und TGR speichere Wert des Knotens "$.path" der aktuellen Anfrage in der Variable "requestPath"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htu.root}" überein mit "${requestScheme}://${requestHost}${requestPath}"
    Und TGR speichere Wert des Knotens "$.path" der aktuellen Anfrage in der Variable "tokenRequestPath"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htu.path}" überein mit "${tokenRequestPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.body.iat}" der aktuellen Anfrage in der Variable "iat"
    Und validiere, dass der Zeitstempel "${iat}" in der Vergangenheit liegt
    # @TA_A_28963_01 - nonce Validierung
    # Guard MUSS prüfen, dass DPoP nonce mit vom /nonce Endpoint ausgegebener nonce übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.nonce}" überein mit "${tokenNonce}"

  @A_25644-01
  @A_25766
  @A_25766
  @A_25767
  @A_26661
  @A_27007
  @A_27802-02
  @TA_A_25644-01_05
  @TA_A_25766_01
  @TA_A_25767_01
  @TA_A_26661_01
  @TA_A_27007_01
  @TA_A_27802-02_01
  @TA_A_27802-02_02
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: Prüfe client-assertion-jwt im Token Exchange Request Body
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_id"
    Und TGR speichere Wert des Knotens "$.body.client_id" der aktuellen Anfrage in der Variable "CLIENT_ID"

    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_JWT"
    Und decodiere und validiere "${CLIENT_ASSERTION_JWT}" gegen Schema "schemas/v_1_0/client-assertion-jwt.yaml"

    ## Client Assertion Header
    # A_27802-02 Algorithmus ist akzeptabel
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.alg" überein mit "ES256"
    # Client Assertion Typ: das Schema erfordert "jwt", allgemeine Convention ist "JWT"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.typ" überein mit "(?i)jwt"

    ## Client Assertion JWT Key
    # TA_A_25766_01 - gemSpec_Krypt-konforme Client-Instance-Key-Parameter
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.jwk.use" überein mit "sig"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.jwk.kty" überein mit "EC"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.jwk.crv" überein mit "^(P-256|brainpoolP256r1)$"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.header.jwk.x" der aktuellen Anfrage in der Variable "clientAssertionJwkX"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.header.jwk.y" der aktuellen Anfrage in der Variable "clientAssertionJwkY"
    Und decodiere Base64Url "${clientAssertionJwkX}" und prüfe, dass die Länge 256 bit ist
    Und decodiere Base64Url "${clientAssertionJwkY}" und prüfe, dass die Länge 256 bit ist
    Und TGR prüfe aktueller Request enthält nicht Knoten "$.body.client_assertion.header.jwk.d"
    Und verifiziere die ES256 Signatur des JWT "${CLIENT_ASSERTION_JWT}"

    ## Client Assertion Payload
    # A_27802-02 - issuer enthält den erwarteten Aussteller (== client_id)
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.iss" überein mit "${CLIENT_ID}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.sub" überein mit "${CLIENT_ID}"

    # A_27802-02: audience enthält den beabsichtigten Empfänger.
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.aud.0" überein mit "https://${zeta_base_url}${paths.guard.tokenEndpointPath}"
    # A_27802-02: das token darf noch nicht abgelaufen sein.
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.exp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_EXP"
    Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_EXP}" in der Zukunft liegt
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.attestation_timestamp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_TIMESTAMP"
    Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_EXP}" später als "${CLIENT_ASSERTION_TIMESTAMP}" liegt

    ## Request Body
    Und TGR prüfe aktueller Request enthält Knoten "$.body.grant_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

  @A_27802-02
  @TA_A_27802-02_01
  @TA_A_27802-02_02
  @MASVS-CRYPTO
  Szenario: ZETA Guard akzeptiert ein gültiges Client Assertion JWT
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_JWT"
    Und verifiziere die ES256 Signatur des JWT "${CLIENT_ASSERTION_JWT}"

  @A_25762-01
  @TA_A_25762-01_02
  @dev
  @MASVS-AUTH
  Szenario: Nutzerauthentifizierung mittels SM(C)-B signiertem Subject Token
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "tokenNonce"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "$.body.client_registration_by_auth_server.*.client_id" der aktuellen Antwort in der Variable "client_id"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body.subject_token" der aktuellen Anfrage in der Variable "SUBJECT_TOKEN"
    Und decodiere und validiere "${SUBJECT_TOKEN}" gegen Schema "schemas/v_1_0/subject-token-smb.yaml"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"

    #[RFC7523] - JWT-Subject Token Pflichtfelder
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.header.typ"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.header.x5c"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.header.alg"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.iss"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.sub"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.aud"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.iat"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.exp"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.nonce"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.body.jti"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token.signature"

    #[RFC 7523] - Werte auf Gültigkeit prüfen
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.header.alg" überein mit "ES256"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.header.typ" überein mit "JWT"
    Und TGR speichere Wert des Knotens "$.body.subject_token.body.exp" der aktuellen Anfrage in der Variable "subjectTokenExp"
    Und TGR speichere Wert des Knotens "$.body.subject_token.body.iat" der aktuellen Anfrage in der Variable "subjectTokenIat"
    Und validiere, dass der Zeitstempel "${subjectTokenExp}" später als "${subjectTokenIat}" liegt

    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.aud.0" überein mit "${paths.guard.audPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.nonce" überein mit "${tokenNonce}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.iss" überein mit "${client_id}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.sub" überein mit "${SMCB-INFO.telematikId}"
    Und TGR speichere Wert des Knotens "$.body.subject_token.body.jti" der aktuellen Anfrage in der Variable "jti"

    #[RFC7523] - Optionale Felder
    Und prüfe aktuelle Anfrage: der Knoten "$.body.subject_token.body.nbf" ist nicht vorhanden oder früher als jetzt

    ## Request Body
    Und TGR prüfe aktueller Request enthält Knoten "$.body.grant_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_id"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_id" überein mit "${client_id}"

  @A_25766
  @TA_A_25766_02
  @MASVS-CRYPTO
  Szenario: Nutzerauthentifizierung - Client sendet DPoP Header und Access Token
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "tokenNonce"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"

    # Token Response Validierung
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.token_type" überein mit "DPoP"

    # DPoP JWT Validierung
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "dpopJwt"
    Und decodiere und validiere "${dpopJwt}" gegen Schema "schemas/v_1_0/dpop-token.yaml"
    Und verifiziere ES256 Signatur von DPoP JWT "${dpopJwt}"
    Und berechne JKT aus DPoP JWT "${dpopJwt}" und speichere in Variable "dpopJwtJkt"
    # @TA_A_25663_01 - Token Binding: cnf.jkt muss mit DPoP Public Key Thumbprint übereinstimmen
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.access_token.body.cnf.jkt" überein mit "${dpopJwtJkt}"

    # DPoP Header Validierung
    # @TA_A_28963_01 - typ muss "dpop+jwt" sein
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.typ}" überein mit "dpop+jwt"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.alg}" überein mit "ES256"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.kty}"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.root}" der aktuellen Anfrage in der Variable "dpopHeader"
    Und prüfe dass jwk in "${dpopHeader}" keine privaten Key-Teile enthält

    # DPoP Payload Validierung
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.jti}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htm}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htu.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.iat}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htm}" überein mit "POST"
    Und TGR speichere Wert des Knotens "${headers.xForwardedProto}" der aktuellen Anfrage in der Variable "requestScheme"
    Und TGR speichere Wert des Knotens "${headers.xForwardedHost}" der aktuellen Anfrage in der Variable "requestHost"
    Und TGR ersetze ":443$" mit "" im Inhalt der Variable "requestHost"
    Und TGR speichere Wert des Knotens "$.path" der aktuellen Anfrage in der Variable "requestPath"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htu.root}" überein mit "${requestScheme}://${requestHost}${requestPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.body.iat}" der aktuellen Anfrage in der Variable "iat"
    Und validiere, dass der Zeitstempel "${iat}" in der Vergangenheit liegt
    # @TA_A_28963_01 - nonce Validierung
    # Guard MUSS prüfen, dass DPoP nonce mit vom /nonce Endpoint ausgegebener nonce übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.nonce}" überein mit "${tokenNonce}"

  # US2 @A_27802-02
  # US2 @TA_A_27802-02_01
  # US2 @TA_A_27802-02_02
  # US2 @MASVS-CRYPTO
  # US2 Szenario: ZETA Guard akzeptiert ein verschachteltes Client Assertion JWT mit cty JWT
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    # US2 Und TGR setze lokale Variable "tokenRequestCondition" auf ".*${paths.guard.tokenEndpointPath}"

    # US2 Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "variant.name" auf Wert "nested_cty_jwt_valid_inner" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${tokenRequestCondition}" und 1 Ausführungen und ersetze JWK
    # US2 Und TGR lösche aufgezeichnete Nachrichten
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.header.cty" überein mit "JWT"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "NESTED_CLIENT_ASSERTION"
    # US2 Und prüfe die JWT-Variante "nested_cty_jwt_valid_inner" in "${NESTED_CLIENT_ASSERTION}" hat lokal die erwartete Signaturintegrität
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

  @A_25337
  @A_25338-01
  @A_25644-01
  @TA_A_25337_01
  @TA_A_25338-01_01
  @TA_A_25338-01_02
  @TA_A_25338-01_03
  @TA_A_25644-01_05
  @dev
  @MASVS-AUTH
  Szenario: Client Assertion JWT enthält Software Attestation für Linux
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # TA_A_25338-01_01 - Validierung gegen client-assertion-jwt.yaml
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_JWT"
    Und decodiere und validiere "${CLIENT_ASSERTION_JWT}" gegen Schema "schemas/v_1_0/client-assertion-jwt.yaml"
    Und verifiziere die ES256 Signatur des JWT "${CLIENT_ASSERTION_JWT}"
    # TA_A_25338-01_01 - Parameter "grant_type" gemäß gemSpec_ZETA#5.11.2.5.1,Step 6
    Und TGR prüfe aktueller Request enthält Knoten "$.body.grant_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    # TA_A_25338-01_01 - Parameter "subject_token_type" gemäß gemSpec_ZETA#5.11.2.5.1,Step 6
    Und TGR prüfe aktueller Request enthält Knoten "$.body.subject_token_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
    # TA_A_25338-01_01 - Parameter "client_assertion_type" gemäß gemSpec_ZETA#5.11.2.5.1,Step 6
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion_type"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"

    # Client statement enthält Product Id, welche unterschiedlich ist für Windows/Linux
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.platform" überein mit "linux"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement" der aktuellen Anfrage in der Variable "CLIENT_STATEMENT"
    Und validiere "${CLIENT_STATEMENT}" gegen Schema "schemas/v_1_0/client-statement.yaml"

    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.attestation_timestamp"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.exp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_EXP"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.attestation_timestamp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_TIMESTAMP"
    Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_EXP}" später als "${CLIENT_ASSERTION_TIMESTAMP}" liegt
    Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_TIMESTAMP}" in der Vergangenheit liegt

    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture.attestation_challenge"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture.public_key"
    # TA_A_25337_01: product_id entspricht dem registrierten Produkt
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture.product_id" der aktuellen Anfrage in der Variable "PRODUCT_ID_INSTANCE_1"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.product_id" überein mit "${testdata.product_id}"
    # TA_A_25338-01_02: product_id folgt dem erlaubten Format
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.product_id" überein mit "${regex.product_id}"
    # TA_A_25338-01_03: product_version folgt dem erlaubten Format
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.product_version" überein mit "${regex.product_version}"

    ## client assertion enthält client statement mit attestation_data und client_id
    Und TGR speichere Wert des Knotens "$.body.client_id" der aktuellen Anfrage in der Variable "CLIENT_ID"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.sub" überein mit "${CLIENT_ID}"

    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture" der aktuellen Anfrage in der Variable "POSTURE"
    Und validiere "${POSTURE}" gegen Schema "schemas/v_1_0/posture-software.yaml"

    # TA_A_25337_01: product_id wird in jeder Clientsystem-Instanz verwendet
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.product_id" überein mit "${PRODUCT_ID_INSTANCE_1}"

  # US2 @A_25644-01
  # US2 @TA_A_25644-01_03
  # US2 @dev
  # US2 @tpm_environment
  # US2 @MASVS-AUTH
  # US2 Szenario: Client Assertion JWT enthält TPM Attestation für Linux
    # US2 Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_id"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_id" der aktuellen Anfrage in der Variable "CLIENT_ID"

    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_JWT"
    # US2 Und decodiere und validiere "${CLIENT_ASSERTION_JWT}" gegen Schema "schemas/v_1_0/client-assertion-jwt.yaml"
    # US2 Und verifiziere die ES256 Signatur des JWT "${CLIENT_ASSERTION_JWT}"

    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.platform" überein mit "linux"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.sub" überein mit "${CLIENT_ID}"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement" der aktuellen Anfrage in der Variable "CLIENT_STATEMENT"
    # US2 Und validiere "${CLIENT_STATEMENT}" gegen Schema "schemas/v_1_0/client-statement.yaml"

    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.attestation_timestamp"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.exp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_EXP"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.attestation_timestamp" der aktuellen Anfrage in der Variable "CLIENT_ASSERTION_TIMESTAMP"
    # US2 Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_EXP}" später als "${CLIENT_ASSERTION_TIMESTAMP}" liegt
    # US2 Und validiere, dass der Zeitstempel "${CLIENT_ASSERTION_TIMESTAMP}" in der Vergangenheit liegt
    # US2 Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion.body.client_statement.posture"
    # US2 Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture" der aktuellen Anfrage in der Variable "POSTURE"
    # US2 Und validiere "${POSTURE}" gegen Schema "schemas/v_1_0/posture-tpm.yaml"

  @A_25645-01
  @A_25650
  @A_26972-02
  @TA_A_25645-01_01
  @TA_A_25650_02
  @TA_A_26972-02_01
  @TA_A_26972-02_02
  @TA_A_26972-02_03
  @TA_A_26972-02_04
  @MASVS-AUTH
  Szenario: PDP Client Registrierung - TI-Identität in Attestation - Bindung TelematikID
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "$.body.client_registration_by_auth_server.*.client_id" der aktuellen Antwort in der Variable "clientId"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
    Und TGR speichere Wert des Knotens "$.body.subject_token" der aktuellen Anfrage in der Variable "SUBJECT_TOKEN"
    Und decodiere und validiere "${SUBJECT_TOKEN}" gegen Schema "schemas/v_1_0/subject-token-smb.yaml"
    #TA_A_25645-01_01 SMCB Signaturprüfung
    Und verifiziere die ES256 Signatur des JWT "${SUBJECT_TOKEN}"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"

    # Prüfe die Client-ID und die Telematik ID in der Attestation
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.iss" überein mit "${clientId}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_id" überein mit "${clientId}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.iss" überein mit "${clientId}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.subject_token.body.sub" überein mit "${SMCB-INFO.telematikId}"

    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    #TA_A_26972-02_01 identifier
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.authorization.dpopToken.body.sub}" überein mit "${SMCB-INFO.telematikId}"
    #TA_A_26972-02_02 commonName
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.authorization.dpopToken.body.common_name}" überein mit "${SMCB-INFO.commonName}"
    #TA_A_26972-02_03 professionOID
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.authorization.dpopToken.body.profession_oid}" überein mit "${SMCB-INFO.professionId}"
    #TA_A_26972-02_04 optional organizationName
    Und prüfe aktuelle Anfrage der Knoten "${headers.authorization.dpopToken.body.organization_name}" ist nicht vorhanden oder gleich "${SMCB-INFO.organizationName}"
