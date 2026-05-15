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

@UseCase_01_22
Funktionalität: Client_ressource_anfrage_fachdienst_PoPP-Header_SC_200

  @A_26477
  @TA_A_26477_05 # Signatur muss mathematisch gültig sein
  @TA_A_26477_08 # popp-token.actorId == access_token.sub
  @MASVS-AUTH
  Szenario: PoPP Token Signatur und actorId werden validiert
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"
    Und hole frisches PoPP Token aus dem Generator für Akteur "${SMCB-INFO.telematikId}" und Profession "${SMCB-INFO.professionId}" und speichere in der Variable "PoPP_TOKEN"

    # Sende Resource Anfrage
    Wenn TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}" mit folgenden Headern:
      | PoPP | ${PoPP_TOKEN} |

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"

    # "PoPP Token werden im Request Header PoPP übertragen".
    Und TGR speichere Wert des Knotens "${headers.popp.root}" der aktuellen Anfrage in der Variable "PoPP_TOKEN"

    # TA_A_26477_05 - PEP HTTP Proxy - PoPP Token Validierung - Signatur mathematisch gültig
    Und verifiziere die ES256 Signatur des JWT "${PoPP_TOKEN}"

    # TA_A_26477_08 - PEP HTTP Proxy - PoPP Token Validierung - Übereinstimmung von claim
    Dann TGR finde die letzte Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.authorization.dpopToken.body.sub}" der aktuellen Anfrage in der Variable "ACCESS_TOKEN_SUB"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.popp.body.actorId}" überein mit "${ACCESS_TOKEN_SUB}"

  @A_26477
  @deployment_modification
  @TA_A_26477_02 # Gültigkeitsdauer seit Ausstellung
  @MASVS-AUTH
  Szenario: PoPP Token Gültigkeitsdauer seit Ausstellung wird validiert
    Gegeben sei setze die PoPP Token Gültigkeit im ZETA Deployment auf "300s"
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.subject_token.header.x5c.0" der aktuellen Anfrage in der Variable "smcbCertificate"
    Und schreibe Daten aus dem SMC-B Zertifikat "${smcbCertificate}" in die Variable "SMCB-INFO"
    Und hole frisches PoPP Token aus dem Generator für Akteur "${SMCB-INFO.telematikId}" und Profession "${SMCB-INFO.professionId}" und speichere in der Variable "PoPP_TOKEN"
    Und TGR setze lokale Variable "poppTokenMaxAgeSeconds" auf "300"

    # Sende Resource Anfrage
    Wenn TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}" mit folgenden Headern:
      | PoPP | ${PoPP_TOKEN} |

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # Zeitstempel "iat" ist nicht älter als konfiguriert
    Und TGR speichere Wert des Knotens "${headers.popp.body.iat}" der aktuellen Anfrage in der Variable "PoPP_TOKEN_IAT"
    Und validiere, dass der Zeitstempel "${PoPP_TOKEN_IAT}" in der Vergangenheit liegt
    Und validiere, dass der Zeitstempel "${PoPP_TOKEN_IAT}" höchstens "${poppTokenMaxAgeSeconds}" Sekunden alt ist

  @A_26477
  @deployment_modification
  @TA_A_26477_03 # Ausstellungszeitpunkt liegt im Quartal des Prüfzeitpunkts
  @MASVS-AUTH
  Szenario: PoPP Token Ausstellungszeitpunkt liegt im Quartal des Prüfzeitpunkts
    Gegeben sei setze die PoPP Token Gültigkeit im ZETA Deployment auf "quarter"
    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # Sende Resource Anfrage
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # Der Prüfzeitpunkt ist der aktuelle Validierungszeitpunkt.
    Und TGR speichere Wert des Knotens "${headers.popp.body.iat}" der aktuellen Anfrage in der Variable "PoPP_TOKEN_IAT"
    Und validiere, dass der Zeitstempel "${PoPP_TOKEN_IAT}" im aktuellen Quartal liegt

  @A_25669-01
  @A_26452
  @A_26477
  @TA_A_25669-01_05
  @TA_A_26452_03
  @TA_A_26477_12 # vorhandenes und noch gültiges JWKS wird verwendet
  @TA_A_26477_08
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: PoPP Token Validation - vorhandenes gültiges JWKS wird verwendet
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR setze lokale Variable "poppSignedJwksPath" auf "${paths.popp.signedJwks}"
    Und TGR setze lokale Variable "poppSignedJwksResponseCondition" auf "isResponse && request.path =~ '.*${poppSignedJwksPath}'"
    Und TGR setze lokale Variable "poppDiscoveryCacheControl" auf "public, max-age=5"
    Und Setze im TigerProxy für die Nachricht "${poppSignedJwksResponseCondition}" die Manipulation auf Feld "${headers.cacheControl}" und Wert "${poppDiscoveryCacheControl}"

    # Vorbereitung: erster Abruf stellt sicher, dass ein gültiges JWKS vorliegt.
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "${headers.popp.root}" der aktuellen Anfrage in der Variable "PoPP_TOKEN"
    Und verifiziere die ES256 Signatur des JWT "${PoPP_TOKEN}"

    # TA_A_26477_12 - vorhandenes und noch gültiges JWKS wird verwendet.
    # Ein erneuter Download wird hier absichtlich gestört; der Abruf muss dennoch mit dem
    # bereits geladenen gültigen JWKS erfolgreich bleiben.
    Und Setze im TigerProxy für die Nachricht "${poppSignedJwksResponseCondition}" die Manipulation auf Feld "$.responseCode" und Wert "500" und 1 Ausführungen
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und prüfe, dass keine aufgezeichnete Anfrage den Pfad "${poppSignedJwksPath}" hat
    Und TGR speichere Wert des Knotens "${headers.popp.root}" der aktuellen Anfrage in der Variable "PoPP_TOKEN"
    Und verifiziere die ES256 Signatur des JWT "${PoPP_TOKEN}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.authorization.dpopToken.body.sub}" der aktuellen Anfrage in der Variable "ACCESS_TOKEN_SUB"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    # @TA_A_26452_03
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.popp.body.actorId}" überein mit "${ACCESS_TOKEN_SUB}"

  @A_26477
  @deployment_modification
  @popp_deployment_toggle
  @TA_A_26477_01
  @MASVS-AUTH
  Szenario: PoPP Token Validierung ist pro Endpunkt konfigurierbar
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.popp.body.insurerId}" der aktuellen Anfrage in der Variable "PoPP_INSURER_ID"
    Und TGR setze lokale Variable "PoPP_PRIVATE_KEY" auf "!{file('src/test/resources/keys/popp-token-foreign_ecKey.pem')}"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"
    Dann Setze im TigerProxy für JWT in "${headers.popp.strict}" das Feld "body.insurerId" auf Wert "${PoPP_INSURER_ID}" mit privatem Schlüssel "${PoPP_PRIVATE_KEY}" für Pfad "${pathCondition}" und 2 Ausführungen und ersetze JWK

    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und deaktiviere die PoPP Token Verifikation für die Route "/pep/" im ZETA Deployment
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.popp.body.insurerId}" der mit "${PoPP_INSURER_ID}" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und aktiviere die PoPP Token Verifikation für die Route "/pep/" im ZETA Deployment
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.popp.body.insurerId}" der mit "${PoPP_INSURER_ID}" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "403"

  @A_26477
  @TA_A_26477_07
  @longrunning
  @MASVS-AUTH
  Szenario: PoPP JWKS wird vor Ablauf aktualisiert
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR setze lokale Variable "poppSignedJwksPath" auf "${paths.popp.signedJwks}"
    Und TGR setze lokale Variable "poppSignedJwksResponseCondition" auf "isResponse && request.path =~ '.*${poppSignedJwksPath}'"
    Und TGR setze lokale Variable "poppJwksCacheControl" auf "public, max-age=5"
    Und TGR setze Anfrage Timeout auf 10 Sekunden
    Und Setze im TigerProxy für die Nachricht "${poppSignedJwksResponseCondition}" die Manipulation auf Feld "${headers.cacheControl}" und Wert "${poppJwksCacheControl}" und 2 Ausführungen

    # Erster Ressource Abruf triggert JWKS-Download mit kurzer Cache-Dauer
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${poppSignedJwksPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.cacheControl}" überein mit "(?i).*max-age *= *5.*"

    # TA_A_26477_07 - über kurze Cache-Control-Dauer wird ein JWKS-Update vor Ablauf erzwungen
    Dann TGR finde die nächste Anfrage mit dem Pfad "${poppSignedJwksPath}"
    Und prüfe, dass die aktuelle Anfrage mit Pfad "${poppSignedJwksPath}" vor Ablauf von 5 Sekunden seit der vorherigen Anfrage mit diesem Pfad gesendet wurde
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
