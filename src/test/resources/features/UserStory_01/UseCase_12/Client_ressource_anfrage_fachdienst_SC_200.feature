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

@UseCase_01_12
Funktionalität: Client_ressource_anfrage_fachdienst_SC_200_integrationstest

  @A_26195
  @A_26639
  @TA_A_26195_01
  @TA_A_26639_01
  @critical
  @websocket
  @MASVS-NETWORK
  Szenario: Ingress und PEP HTTP Proxy unterstützt WebSocket Verbindung
    # Ein WebSocket-Roundtrip sollte hier reichen, allerdings könnte man auch noch die Verbindung
      # Ingress <-> PEP HTTP Proxy über den Standalone Tiger Proxy testen.
    Wenn eine WebSocket Verbindung zu "${paths.client.websocketBaseUrl}" geöffnet wird
    Dann wird die WebSocket Verbindung geschlossen

  @A_25660
  @A_25766
  @A_25767
  @A_26492-02
  @A_28963
  @TA_A_25660_01
  @TA_A_25660_04
  @TA_A_25766_02
  @TA_A_25767_02
  @TA_A_26492-02_02
  @TA_A_28963_01
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: DPoP Resource Request - Client sendet DPoP Proof mit Access Token für geschützte Ressource
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # save the access token from /token response for later ath check
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.access_token" der aktuellen Antwort in der Variable "accessToken"

    # TA_A_25660_04 - Refresh Token muss vorhanden sein
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.refresh_token"

    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.message" überein mit "Hello ZETA!"

    # Resource Request Validierung
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.authorization.lenient}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.authorization.lenient}" überein mit "(?i)^DPoP .*"

    # DPoP JWT Validierung
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "resourceDpopJwt"
    Und decodiere und validiere "${resourceDpopJwt}" gegen Schema "schemas/v_1_0/dpop-token.yaml"
    Und verifiziere ES256 Signatur von DPoP JWT "${resourceDpopJwt}"

    # DPoP Header Validierung
    # @TA_A_28963_01 - typ muss "dpop+jwt" sein
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.typ}" überein mit "dpop+jwt"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.alg}" überein mit "ES256"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.header.jwk.kty}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.jwk.kty}" überein mit "EC"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.header.jwk.crv}" überein mit "P-256"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.jwk.x}" der aktuellen Anfrage in der Variable "resourceDpopJwkX"
    Und TGR speichere Wert des Knotens "${headers.dpop.header.jwk.y}" der aktuellen Anfrage in der Variable "resourceDpopJwkY"
    Und decodiere Base64Url "${resourceDpopJwkX}" und prüfe, dass die Länge 256 bit ist
    Und decodiere Base64Url "${resourceDpopJwkY}" und prüfe, dass die Länge 256 bit ist
    Und TGR speichere Wert des Knotens "${headers.dpop.header.root}" der aktuellen Anfrage in der Variable "resourceDpopHeader"
    Und prüfe dass jwk in "${resourceDpopHeader}" keine privaten Key-Teile enthält

    # DPoP Payload Validierung
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.jti}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htm}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.htu.root}"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.iat}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htm}" überein mit "GET"
    Und TGR speichere Wert des Knotens "${headers.xForwardedProto}" der aktuellen Anfrage in der Variable "requestScheme"
    Und TGR speichere Wert des Knotens "${headers.xForwardedHost}" der aktuellen Anfrage in der Variable "requestHost"
    Und TGR ersetze ":443$" mit "" im Inhalt der Variable "requestHost"
    Und TGR speichere Wert des Knotens "$.path" der aktuellen Anfrage in der Variable "requestPath"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.htu.root}" überein mit "${requestScheme}://${requestHost}${requestPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.body.iat}" der aktuellen Anfrage in der Variable "resourceIat"
    Und validiere, dass der Zeitstempel "${resourceIat}" in der Vergangenheit liegt

    # Access Token Hash (ath) Validierung - nur bei Resource Requests
    Und TGR prüfe aktueller Request enthält Knoten "${headers.dpop.body.ath}"
    Und berechne SHA256 Hash von "${accessToken}" und speichere in Variable "expectedAth"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.ath}" überein mit "${expectedAth}"

    Und TGR warte auf eine Nachricht, in der Knoten "$.path" mit "^${paths.fachdienst.helloZetaPath}" übereinstimmt
    Dann TGR finde die letzte Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # TA_A_26492-02_02 - PEP HTTP Proxy - Weiterleitung von Client-Daten - Defaulteinstellung
    Und TGR prüfe aktueller Request enthält nicht Knoten "${headers.zeta.clientData.root}"

    # Nonce wird bei Resource Requests nicht mitgeschickt

  # US2 @A_26561
  # US2 @TA_A_26561_01
  # US2 Szenario: PEP HTTP Proxy nutzt gecachte Response-Inhalte
  # US2   Und TGR setze lokale Variable "cachedMessage" auf "Hello ZETA (cached)"
  # US2   Und TGR setze lokale Variable "cacheCondition" auf "isResponse && request.path =~ '^${paths.fachdienst.helloZetaPath}'"
  # US2   Dann Setze im TigerProxy für die Nachricht "${cacheCondition}" die Manipulation auf Feld "$.body.message" und Wert "${cachedMessage}" und 1 Ausführungen

  # US2   Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
  # US2   Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.message" überein mit "${cachedMessage}"

  # US2   Und Alle Manipulationen im TigerProxy werden gestoppt
  # US2   Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.message" überein mit "${cachedMessage}"

  @A_25669-01
  @TA_A_25669-01_08
  @deployment_modification
  @popp_deployment_toggle
  @MASVS-AUTH
  Szenario: PEP fügt keinen zeta-popp-token-content ein, wenn kein PoPP-Header mitgeschickt wurde, und entfernt ursprünglich gleichnamige Header
    Gegeben sei deaktiviere die PoPP Token Verifikation für die Route "/pep/" im ZETA Deployment

    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR setze lokale Variable "poppHeaderCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    # popp Header löschen
    Und Setze im TigerProxy für die Nachricht "${poppHeaderCondition}" die Regex-Manipulation auf Feld "$.header" mit Regex "${headers.popp.lineRegex}" und Wert ""
    # zeta-popp-token-content Header hinzufügen
    Und Setze im TigerProxy für die Nachricht "${poppHeaderCondition}" die Manipulation auf Feld "${headers.zeta.poppTokenContent.strict}" und Wert "FAKE_POPP_CONTENT"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Prüfe Request VOR PEP - PoPP-Header ohne Token-Inhalt
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktueller Request enthält nicht Knoten "${headers.popp.root}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.zeta.poppTokenContent.root}" überein mit "FAKE_POPP_CONTENT"

    # Prüfe Request NACH PEP - zeta-popp-token-content darf nicht gesetzt sein
    Dann TGR finde die nächste Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaPath}"
    Und TGR prüfe aktueller Request enthält nicht Knoten "${headers.popp.root}"
    Und TGR prüfe aktueller Request enthält nicht Knoten "${headers.zeta.poppTokenContent.root}"

    Und aktiviere die PoPP Token Verifikation für die Route "/pep/" im ZETA Deployment

  @A_27725-01
  @TA_A_27725-01_02
  @dev
  @MASVS-RESILIENCE
  Szenario: Telemetrie-Daten enthalten bei erfolgreicher Operation den HTTP-Statuscode 200
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR warte auf eine Nachricht, in der Knoten "$.path" mit "^${paths.fachdienst.helloZetaPath}" übereinstimmt
    Und TGR finde die letzte Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.path" der aktuellen Anfrage in der Variable "resourcePath"

    # Warte auf Telemetrie-Ingestion (Lieferintervall standardmäßig 60s)
    Und warte 70 Sekunden

    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                   | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.containerName.telemetryDataService} AND resource.service.name:${telemetry.service.httpProxy} AND body:\"${resourcePath}\" AND http.response.status_code:200 AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.hits.hits.0._source['http.response.status_code']" überein mit "200"

  # US2 @A_28808
  # US2 @TA_A_28808_05
  # US2 @dev
  # US2 Szenario: Sessiondaten nach session_expiry nicht mehr verwendbar
  # US2   # TTL-Werte als Variablen definieren (in Sekunden)
  # US2   Wenn TGR setze lokale Variable "accessTokenTtl" auf "30"
  # US2   Und TGR setze lokale Variable "refreshTokenTtl" auf "100"

  # US2   # OPA Decision manipulieren: Kurze TTL für Refresh Token setzen
  # US2   # Die OPA-Response bestimmt die tatsächliche Token-Gültigkeit im Authorization Server
  # US2   Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
  # US2   Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.refresh_token" und Wert "${refreshTokenTtl}" und 1 Ausführungen
  # US2   Und Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 1 Ausführungen

  # US2   # Client zurücksetzen und ersten Token holen
  # US2   Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
  # US2   Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
  # US2   Und TGR speichere Wert des Knotens "$.body.access_token.body.sid" der aktuellen Antwort in der Variable "oldSessionId"
  # US2   Und TGR speichere Wert des Knotens "$.body.refresh_token.body.exp" der aktuellen Antwort in der Variable "session_expiry"

  # US2   # Warte bis session_expiry erreicht ist
  # US2   Und warte "${refreshTokenTtl}" Sekunden
  # US2   Und validiere, dass der Zeitstempel "${session_expiry}" in der Vergangenheit liegt

  # US2   # Nachrichten löschen, damit nur der nächste Resource-Request geprüft wird
  # US2   Und TGR lösche aufgezeichnete Nachrichten

  # US2   # DPoP-Key holen und Access Token manipulieren (jti alt)
  # US2   Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
  # US2   Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
  # US2   Und TGR setze lokale Variable "ecKeyFilePath" auf "${paths.guard.ecKeyFile}"
  # US2   Und TGR setze lokale Variable "signingKey" auf "!{file('${ecKeyFilePath}')}"
  # US2   Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"

  # US2   Dann Setze im TigerProxy für Access Token das Feld "body.sid" auf Wert "${oldSessionId}" mit Access Token Key "${signingKey}" und DPoP Key "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen
  # US2   Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" nicht überein mit "200"

  # US2   # Überprüfe zusätzlich, dass eine neue Session verwendet wird
  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.access_token.body.sid" nicht überein mit "${oldSessionId}"
  # US2   Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.refresh_token.body.sid" nicht überein mit "${oldSessionId}"
