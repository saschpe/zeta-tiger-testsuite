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

@UseCase_01_09
Funktionalität: Client_authentisierung_und_autorisierung_software_attest_SC_403

  @A_25661
  @A_26661
  @A_26662
  @A_26988
  @A_27401
  @TA_A_25661_03
  @TA_A_26661_04
  @TA_A_26662_01
  @TA_A_26988_05
  @TA_A_26988_07
  @TA_A_27401_01
  @dev
  @MASVS-AUTH
  Szenario: Policy Decision - Zugriffsverweigerung bei allow=false liefert HTTP 403
    # OPA Response manipulieren: allow auf false setzen
    # Bei allow=false muss Authserver mit 403 antworten
    Gegeben sei Setze im TigerProxy für die Nachricht "isResponse" die Manipulation auf Feld "$.body.result.allow" und Wert "false" und 1 Ausführungen

    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # TA_A_27401_01: OPA Response Schema-Validierung
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "PDP_DECISION"
    # TA_A_27401_01 - PDP Policy Engine - Decision Eigenschaften - schemakonform
    Und validiere "${PDP_DECISION}" gegen Schema "schemas/v_1_0/pdp-decision.yaml"

    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.result.allow"
    # Manipulation verifizieren: allow sollte false sein
    # TA_A_25661_03 - PDP Authorization Server - Umsetzung der Policy Decision - Zugriffsverweigerung
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.result.allow" überein mit "false"

    # TA_A_25661_03: Token Request muss mit 403 Forbidden fehlschlagen
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    # TA_A_25661_03 - PDP Authorization Server - Umsetzung der Policy Decision - Zugriffsverweigerung
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"

    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    # TA_A_26662_01 - ZETA Guard, HTTP Fehlerdetails
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
    Und TGR prüfe aktuelle Antwort enthält nicht Knoten "$.body.access_token"
    Und TGR prüfe aktuelle Antwort enthält nicht Knoten "$.body.refresh_token"

    # Warte auf Telemetrie-Ingestion (Lieferintervall standardmäßig 60s)
    Und warte "${testdata.telemetry_wait_seconds}" Sekunden

    # TA_A_26988_05 - Authorization Server: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                                      | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.authorizationServer}" AND body:${paths.guard.tokenEndpointPath} AND body:403 AND severity.number:[13 TO *] AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

    # TA_A_26988_07 - Policy Engine: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                                         | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.policyEngine}" AND body:${paths.opa.decisionPath} AND body:allow AND body:false AND severity.number:[13 TO *] AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

  @A_27496
  @TA_A_27496_01
  @TA_A_27496_02
  @TA_A_27496_03
  @MASVS-RESILIENCE
  Szenario: product_id, product_version und professionOID werden bei jedem Aufruf korrekt verarbeitet und protokolliert
    # Gutfall ohne Manipulation, aber mit gleichzeitiger Suche der drei Werte im Log
    # Für beide Aufrufe wird allow=false erzwungen, damit jeweils ein vollständiger Policy-Request erfolgt
    Gegeben sei TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.allow" und Wert "false" und 1 Ausführungen
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # Erster Aufruf
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture.product_id" der aktuellen Anfrage in der Variable "PRODUCT_ID"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture.product_version" der aktuellen Anfrage in der Variable "PRODUCT_VERSION"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.client_assertion.posture.product_id" überein mit "${PRODUCT_ID}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.client_assertion.posture.product_version" überein mit "${PRODUCT_VERSION}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.user_info.professionOID" überein mit "${SMCB-INFO.professionId}"

    # Telemetrie-/Monitoring-Nachweis: beide Läufe eindeutig korreliert und protokolliert
    Und warte "${testdata.telemetry_wait_seconds}" Sekunden
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                     | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND body:professionOID AND body:${SMCB-INFO.professionId} AND body:product_id AND body:${PRODUCT_ID} AND body:product_version AND body:${PRODUCT_VERSION} AND body:${paths.guard.tokenEndpointPath} | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

  @A_27496
  @TA_A_27496_01
  @TA_A_27496_02
  @TA_A_27496_03
  @MASVS-RESILIENCE
  Szenariogrundriss: product_id, product_version und professionOID werden korrekt verarbeitet und protokolliert
    # Test für manipulierte product_id und product_version
    # Für beide Aufrufe wird allow=false erzwungen, damit jeweils ein vollständiger Policy-Request erfolgt
    Gegeben sei TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.allow" und Wert "false" und 2 Ausführungen

    Und TGR setze lokale Variable "tokenRequestCondition" auf "message.path =~ '.*${paths.guard.tokenEndpointPath}' && message.body.grant_type =~ '.*token-exchange'"
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # Erster Aufruf:
    Und TGR lösche aufgezeichnete Nachrichten
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"
    Und TGR speichere Wert des Knotens "$.body.client_assertion.body.client_statement.posture.<ManipuliertesFeld>" der aktuellen Anfrage in der Variable "ORIGINAL_VALUE"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.client_assertion.posture.<ManipuliertesFeld>" überein mit "${ORIGINAL_VALUE}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.user_info.professionOID" überein mit "${SMCB-INFO.professionId}"

    # Hole einen Private Key über storage (wird für Signatur und JWK-Ersetzung verwendet)
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "privateKey"

    # Zweiter Aufruf: <ManipuliertesFeld> manipuliert
    Und TGR lösche aufgezeichnete Nachrichten
    Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "<JwtField>" auf Wert "<NeuerWert>" mit privatem Schlüssel "${privateKey}" für Pfad "${tokenRequestCondition}" und 1 Ausführungen und ersetze JWK
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificateSecond"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificateSecond}" in die Variable "SMCB-INFO-SECOND"
    # Stelle sicher, dass die Manipulation funktioniert hat
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.client_statement.posture.<ManipuliertesFeld>" überein mit "<NeuerWert>"
    # Prüfe, dass die gleichen Daten an OPA übergeben werden
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.opa.decisionPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.client_assertion.posture.<ManipuliertesFeld>" überein mit "<NeuerWert>"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.input.user_info.professionOID" überein mit "${SMCB-INFO-SECOND.professionId}"

    # Telemetrie-/Monitoring-Nachweis: beide Läufe eindeutig korreliert und protokolliert
    Und warte "${testdata.telemetry_wait_seconds}" Sekunden
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                             | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND body:professionOID AND body:${SMCB-INFO.professionId} AND body:<ManipuliertesFeld> AND body:${ORIGINAL_VALUE} AND body:${paths.guard.tokenEndpointPath} | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                              | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND body:professionOID AND body:${SMCB-INFO-SECOND.professionId} AND body:<ManipuliertesFeld> AND body:<NeuerWert> AND body:${paths.guard.tokenEndpointPath} | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

    Beispiele:
      | ManipuliertesFeld | JwtField                                      | NeuerWert         |
      | product_id        | body.client_statement.posture.product_id      | test-proxy-second |
      | product_version   | body.client_statement.posture.product_version | 9.9.9             |

  @A_25644-01
  @TA_A_25644-01_05
  @MASVS-AUTH
  Szenario: Software Attestation (Linux) - ungültige attestation_challenge wird abgelehnt (Negativtest)
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.discover}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.register}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "$.body.client_private_key" der aktuellen Antwort in der Variable "CLIENT_PRIVATE_KEY"
    Und TGR setze lokale Variable "pathCondition" auf "message.path =~ '.*${paths.guard.tokenEndpointPath}' && message.body.grant_type =~ '.*token-exchange'"

    Dann Setze im TigerProxy für JWT in "$.body.client_assertion" das Feld "body.client_statement.posture.attestation_challenge" auf Wert "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" mit privatem Schlüssel "${CLIENT_PRIVATE_KEY}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.client_assertion.body.client_statement.posture.attestation_challenge" der mit "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.grant_type" überein mit "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
