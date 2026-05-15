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

@UseCase_01_01
Funktionalität: Client_initiale_registrierung_stationaer_SC_201

  @A_26640
  @A_26641
  @A_27266
  @A_27798
  # US2 @A_28422
  @A_28464
  @TA_A_26640_01
  @TA_A_26641_01
  @TA_A_27266_01
  @TA_A_27266_02
  @TA_A_27798_01
  @TA_A_27798_03
  # US2 @TA_A_28422_01
  # US2 @TA_A_28422_03
  @TA_A_28464_01
  Szenario: well-known zu oauth-protected-resource
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthProtectedResourcePath}$"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.host}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.host}" überein mit "${zeta_base_url}(:[0-9]+)?"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.httpVersion" überein mit "HTTP/1.1"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "OPR_WELL_KNOWN"
    Und validiere "${OPR_WELL_KNOWN}" gegen Schema "schemas/v_1_0/opr-well-known.yaml"
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.cacheControl}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.authorization_servers.0"
    Und TGR prüfe aktuelle Antwort enthält nicht Knoten "$.body.authorization_servers.1"

  @A_26640
  # US2 @A_28422
  @TA_A_26640_01
  # US2 @TA_A_28422_01
  # US2 @TA_A_28422_03
  @component
  @no_proxy
  Szenario: well-known zu oauth-protected-resource (Komponententest)
    Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}${paths.guard.wellKnownOAuthProtectedResourcePath}"
    Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthProtectedResourcePath}$"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.host}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.host}" überein mit "${zeta_base_url}(:[0-9]+)?"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.httpVersion" überein mit "HTTP/1.1"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "OPR_WELL_KNOWN"
    Und validiere "${OPR_WELL_KNOWN}" gegen Schema "schemas/v_1_0/opr-well-known.yaml"
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.cacheControl}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.authorization_servers.0"
    Und TGR prüfe aktuelle Antwort enthält nicht Knoten "$.body.authorization_servers.1"

  @A_27798
  # US2 @A_28422
  @TA_A_27798_02
  @TA_A_27798_04
  # US2 @TA_A_28422_01
  # US2 @TA_A_28422_03
  # US2 @TA_A_28422_04
  # US2 @TA_A_28422_06
  @dev
  Szenario: well-known zu oauth-authorization-server
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthServerPath}$"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.host}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.host}" überein mit "${zeta_base_url}(:[0-9]+)?"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "AS_WELL_KNOWN"
    Und validiere "${AS_WELL_KNOWN}" gegen Schema "schemas/v_1_0/as-well-known.yaml"
    Und TGR speichere Wert des Knotens "$.body.jwks_uri" der aktuellen Antwort in der Variable "jwksUri"
    Und TGR assert variable "jwksUri" matches "^https?://[^/]+/.*$"
    Und TGR setze lokale Feature Variable "jwksPath" auf "${jwksUri}"
    Und TGR ersetze "^https?://[^/]+" mit "" im Inhalt der Variable "jwksPath"
    Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}${jwksPath}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${jwksPath}"
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.cacheControl}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"

  @component
  @no_proxy
  Szenario: well-known zu oauth-authorization-server (Komponententest)
    Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}${paths.guard.wellKnownOAuthServerPath}"
    Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthServerPath}$"
    Und TGR prüfe aktueller Request enthält Knoten "${headers.host}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.host}" überein mit "${zeta_base_url}(:[0-9]+)?"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.cacheControl}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "AS_WELL_KNOWN"
    Und validiere "${AS_WELL_KNOWN}" gegen Schema "schemas/v_1_0/as-well-known.yaml"
    Und TGR speichere Wert des Knotens "$.body.jwks_uri" der aktuellen Antwort in der Variable "jwksUri"
    Und TGR assert variable "jwksUri" matches "^https?://[^/]+/.*$"
    Und TGR setze lokale Feature Variable "jwksPath" auf "${jwksUri}"
    Und TGR ersetze "^https?://[^/]+" mit "" im Inhalt der Variable "jwksPath"
    Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}${jwksPath}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${jwksPath}"
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.cacheControl}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *=[ ]*[0-9]+.*"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*public.*"


  @A_27266
  @A_27798
  # US2 @A_28420-01
  # US2 @A_28421-01
  # US2 @A_28425-01
  # US2 @TA_A_28420-01_01
  # US2 @TA_A_28420-01_02
  # US2 @TA_A_28421-01_01
  # US2 @TA_A_28421-01_02
  # US2 @TA_A_28421-01_03
  # US2 @TA_A_28421-01_04
  # US2 @TA_A_28421-01_05
  Szenariogrundriss: etag wird bei der Abfrage der well-known Dokumente verwendet
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # Erste Resourceabfrage: finde aktuellen etag heraus
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Dann TGR finde die nächste Anfrage mit dem Pfad ".*<expected_path>"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "WELL_KNOWN"
    Und validiere "${WELL_KNOWN}" gegen Schema "<schema_path>"
    # US2 # TA_A_28420-01_01, TA_A_28420-01_02
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.eTag.lenient}"
    # US2 Und TGR speichere Wert des Knotens "${headers.eTag.lenient}" der aktuellen Antwort in der Variable "ETAG"

    # US2 # Manipuliere die nächste Response: responseCode = 404 => Folgende Resourceanfrage muss Service Discovery enthalten (A_28426)
    # US2 Und TGR setze lokale Variable "notFoundCondition" auf "isResponse && request.path =^ '${paths.fachdienst.helloZetaPath}'"
    # US2 Und Setze im TigerProxy für die Nachricht "${notFoundCondition}" die Manipulation auf Feld "$.responseCode" und Wert "404"
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # US2  # Zweite Resourceabfrage: Fehler bei Resourceanfrage provoziert erneute Service Discovery Anfrage
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "404"
    # US2 Und Alle Manipulationen im TigerProxy werden gestoppt

    # US2 # Dritte Resourceabfrage: "if-none-match" Header mit etag => Response = 304 und leerer body
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    # US2 Dann TGR finde die nächste Anfrage mit dem Pfad ".*<expected_path>"
    # US2 # TA_A_28421-01_01
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "304"
    # US2 # TA_A_28425-01_01 und TA_A_28425-01_02
    # US2 Und TGR prüfe aktueller Request enthält Knoten "${headers.ifNoneMatch.lenient}"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "${headers.ifNoneMatch.lenient}" überein mit "${ETAG}"
    # US2 # TA_A_28420-01_02
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.eTag.lenient}" überein mit "${ETAG}"
    # US2 # TA_A_28421-01_02
    # US2 Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "RESPONSEBODY"
    # US2 Und TGR prüfe Variable "RESPONSEBODY" stimmt überein mit ""

    # US2 # Manipuliere "if-none-match" Header: ungültiger etag
    # US2 Gegeben sei TGR setze lokale Variable "ifNoneMatchCondition" auf "isRequest && request.path =~ '.*<expected_path>.*'"
    # US2 Dann TGR setze lokale Variable "INVALID_ETAG" auf "${testdata.invalidEtag}"
    # US2 Dann Setze im TigerProxy für die Nachricht "${ifNoneMatchCondition}" die Manipulation auf Feld "${headers.ifNoneMatch.strict}" und Wert "${INVALID_ETAG}"

    # US2 # Reset client => Service Discovery muss bei der nächsten Resourceabfrage ausgeführt werden
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # US2 # Vierte Resourceabfrage: "if-none-match" Header mit ungültigem etag => Response = 200 und vollständiges well-known Dokument
    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    # US2 Dann TGR finde die nächste Anfrage mit dem Pfad ".*<expected_path>"
    # US2 # Überprüfe die Manipulation
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "${headers.ifNoneMatch.strict}" überein mit "${INVALID_ETAG}"
    # US2 # TA_A_28421-01_03
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # US2 # TA_A_28421-01_04
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body" überein mit "${WELL_KNOWN}"
    # US2 # TA_A_28421-01_05
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.eTag.lenient}" überein mit "${ETAG}"

    @TA_A_27266_02
    @TA_A_27798_03
    # US2 @TA_A_28425-01_01
    Beispiele: "/.well-known/oauth-protected-resource"
      | expected_path                                      | schema_path                       |
      | ${paths.guard.wellKnownOAuthProtectedResourcePath} | schemas/v_1_0/opr-well-known.yaml |

    @TA_A_27798_04
    # US2 @TA_A_28425-01_02
    Beispiele: "/.well-known/oauth-authorization-server"
      | expected_path                           | schema_path                      |
      | ${paths.guard.wellKnownOAuthServerPath} | schemas/v_1_0/as-well-known.yaml |


  @A_27266
  @A_27798
  # US2 @A_28420-01
  # US2 @A_28421-01
  # US2 @A_28425-01
  # US2 @TA_A_28420-01_01
  # US2 @TA_A_28420-01_02
  # US2 @TA_A_28421-01_01
  # US2 @TA_A_28421-01_02
  # US2 @TA_A_28421-01_03
  # US2 @TA_A_28421-01_04
  # US2 @TA_A_28421-01_05
  @component
  Szenariogrundriss: etag wird bei der Abfrage der well-known Dokumente vom ZETA Guard bereitgestellt (Komponententest)
    # Erste Anfrage: Finde aktuellen etag heraus
    Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}<expected_path>"
    Dann TGR finde die letzte Anfrage mit dem Pfad ".*<expected_path>"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "WELL_KNOWN"
    Und validiere "${WELL_KNOWN}" gegen Schema "<schema_path>"
    # US2 # TA_A_28420-01_01, TA_A_28420-01_02
    # US2 Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.eTag.lenient}"
    # US2 Und TGR speichere Wert des Knotens "${headers.eTag.lenient}" der aktuellen Antwort in der Variable "ETAG"

    # US2 # Zweite Anfrage: Erzwinge "if-none-match" Header für die well-known Abfrage. Server antwortet "304 Not Modified"
    # US2 Gegeben sei TGR setze lokale Variable "ifNoneMatchCondition" auf "isRequest && request.path =~ '.*<expected_path>.*'"
    # US2 Dann Setze im TigerProxy für die Nachricht "${ifNoneMatchCondition}" die Manipulation auf Feld "${headers.ifNoneMatch.strict}" und Wert "${ETAG}"

    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}<expected_path>"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad ".*<expected_path>"
    # US2 Und TGR prüfe aktueller Request enthält Knoten "${headers.ifNoneMatch.lenient}"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "${headers.ifNoneMatch.lenient}" überein mit "${ETAG}"
    # US2 # TA_A_28421-01_01
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "304"
    # US2 # TA_A_28421-01_02
    # US2 Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "RESPONSEBODY"
    # US2 Und TGR prüfe Variable "RESPONSEBODY" stimmt überein mit ""
    # US2 # TA_A_28420-01_02
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.eTag.lenient}" überein mit "${ETAG}"

    # US2 # Dritte Anfrage: Sende "if-none-match" Header mit falschem etag. Server antwortet 200 und sendet das aktuelle well-known JSON Dokument.
    # US2 Gegeben sei TGR setze lokale Variable "ifNoneMatchCondition" auf "isRequest && request.path =~ '.*<expected_path>.*'"
    # US2 Und TGR setze lokale Variable "INVALID_ETAG" auf "${testdata.invalidEtag}"
    # US2 Dann Setze im TigerProxy für die Nachricht "${ifNoneMatchCondition}" die Manipulation auf Feld "${headers.ifNoneMatch.strict}" und Wert "${INVALID_ETAG}"

    # US2 Wenn TGR sende eine leere GET Anfrage an "${paths.guard.baseUrl}<expected_path>"
    # US2 Dann TGR finde die letzte Anfrage mit dem Pfad ".*<expected_path>"
    # US2 Und TGR prüfe aktueller Request stimmt im Knoten "${headers.ifNoneMatch.lenient}" überein mit "${INVALID_ETAG}"
    # US2 # TA_A_28421-01_03
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # US2 # TA_A_28421-01_04
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body" überein mit "${WELL_KNOWN}"
    # US2 # TA_A_28421-01_05 und TA_A_28420-01_02
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.eTag.lenient}" überein mit "${ETAG}"

    @TA_A_27266_02
    @TA_A_27798_03
    Beispiele: "/.well-known/oauth-protected-resource"
      | expected_path                                      | schema_path                       |
      | ${paths.guard.wellKnownOAuthProtectedResourcePath} | schemas/v_1_0/opr-well-known.yaml |

    @TA_A_27798_04
    Beispiele: "/.well-known/oauth-authorization-server"
      | expected_path                           | schema_path                      |
      | ${paths.guard.wellKnownOAuthServerPath} | schemas/v_1_0/as-well-known.yaml |


  # US2 @A_26668-02
  # US2 @TA_A_26668-02_06
  # US2 @TA_A_26668-02_07
  # US2 @TA_A_26668-02_08
  # US2 @TA_A_26668-02_10
  # US2 @TA_A_26668-02_11
  # US2 @TA_A_26668-02_12
  # US2 @TA_A_26668-02_14
  # US2 @TA_A_26668-02_15
  # US2 @TA_A_26668-02_16
  # US2 @TA_A_26668-02_30
  # US2 @TA_A_26668-02_31
  # US2 @TA_A_26668-02_32
  # US2 @TA_A_26668-02_34
  # US2 @TA_A_26668-02_35
  # US2 @TA_A_26668-02_36
  # US2 @TA_A_26668-02_42
  # US2 @TA_A_26668-02_43
  # US2 @TA_A_26668-02_44
  # US2 Szenario: Rate-Limit Header an relevanten Endpunkten vorhanden
  # US2   # Voraussetzung: Rate-Limit ist auf jedem geprüften Endpunkt konfiguriert.
  # US2   Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
  # US2   Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthProtectedResourcePath}$"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad ".*${paths.guard.wellKnownOAuthServerPath}$"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.registerEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.nonceEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  # US2   Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.limit}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.remaining}"
  # US2   Und TGR prüfe aktuelle Antwort enthält Knoten "${headers.rateLimit.reset}"

  @A_26587-01
  @A_26661
  @A_28465
  @TA_A_26587-01_01
  @TA_A_26661_10
  @TA_A_28465_02
  @dev
  @MASVS-AUTH
  Szenario: Client erfolgreich registrieren (Integrationstest)
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.registerEndpointPath}"
    # TA_A_26661_10 - ZETA Guard - HTTP Statuscodes - Clientregistrierung - 201 Created
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "201"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.client_id"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.client_id_issued_at"
    Und TGR speichere Wert des Knotens "$.body.client_id" der aktuellen Antwort in der Variable "registeredClientId"

    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.token_endpoint_auth_method" überein mit "private_key_jwt"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.grant_types"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.jwks"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.redirect_uris"

    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.registration_client_uri"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.registration_access_token"

    # --- Request validation ---
    Und TGR prüfe aktueller Request stimmt im Knoten "$.method" überein mit "POST"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.contentType}" überein mit "application/json"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_name" überein mit "sdk-client"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.token_endpoint_auth_method"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.grant_types"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.jwks"

    # TA_A_26587-01_01: PDP Datenbank - Kompatibilität zum Authorization Server über registrierte Client-ID im Token Request
    Dann TGR finde die nächste Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.client_assertion"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.iss" überein mit "${registeredClientId}"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_assertion.body.sub" überein mit "${registeredClientId}"

  @A_25738
  @TA_A_25738_08
  @MASVS-RESILIENCE
  Szenario: Telemetrie protokolliert Status/Ergebnis der Client-Registrierung (Platzhalter)
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.registerEndpointPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "201"

    Und warte "2" Sekunden
    # Authentication Server loggt das Ergebnis noch nicht, daher schlägt der Test fehl.
    # TODO: Query anpassen, wenn Log-Eintrag vom Authentication Server generiert wird.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                  | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.containerName.authorizationServer} AND body:clientregistrationresult | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    # Die Existenz von hits.hits.0 bedeutet, dass es mindestens einen Open Telemetry Log-Eintrag für obiges Query gibt.
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

  @A_26661
  @TA_A_26661_10
  @component
  @dev
  @no_proxy
  @MASVS-AUTH
  Szenario: Client erfolgreich registrieren (Komponententest)
    Wenn TGR sende eine POST Anfrage an "${paths.guard.baseUrl}${paths.guard.registerEndpointPath}" mit ContentType "application/json" und folgenden mehrzeiligen Daten:
      """
      !{file('src/test/resources/mocks/register-request.json')}
      """
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.registerEndpointPath}"
    # TA_A_26661_10
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "201"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.client_id"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.client_id_issued_at"

    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.token_endpoint_auth_method" überein mit "private_key_jwt"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.grant_types"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.jwks"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.redirect_uris"

    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.registration_client_uri"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.registration_access_token"

    # --- Request validation ---
    Und TGR prüfe aktueller Request stimmt im Knoten "$.method" überein mit "POST"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.contentType}" überein mit "application/json"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.client_name" überein mit "sdk-client"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.token_endpoint_auth_method"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.grant_types"
    Und TGR prüfe aktueller Request enthält Knoten "$.body.jwks"
