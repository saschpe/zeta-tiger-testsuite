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

@UseCase_01_16
Funktionalität: Client Ressource Anfrage Fachdienst sc 401

  @A_25663
  @TA_A_25663_01
  @MASVS-AUTH
  Szenario: Ressourcenanfrage mit DPoP Key aus vorheriger Client-Session wird vom PEP abgelehnt
    # TA_A_25663_01: Der Authorization Server bindet den ausgegebenen Access Token an den DPoP Key des Token Requests.
    # A_25667: Der PEP HTTP Proxy lehnt den Resource Request ab, wenn Access Token Binding und DPoP Proof nicht übereinstimmen.

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "attackerDpopKey"

    Wenn TGR setze lokale Variable "dpopCondition" auf ".*${paths.guard.tokenEndpointPath}"
    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "body.jti" auf Wert "attacker-session-token-jti" mit privatem Schlüssel "${attackerDpopKey}" für Pfad "${dpopCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.body.jti}" der mit "attacker-session-token-jti" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "tokenDpopJwt"
    Und berechne JKT aus DPoP JWT "${tokenDpopJwt}" und speichere in Variable "tokenDpopJkt"
    # @TA_A_25663_01 - Token Binding: cnf.jkt muss mit dem DPoP Public Key Thumbprint des Token Requests übereinstimmen
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.access_token.body.cnf.jkt" überein mit "${tokenDpopJkt}"

    # A_25667 - Resource Request wird abgelehnt, weil der Client nach Reset einen anderen DPoP Key verwendet
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_25663
  @TA_A_25663_01
  @MASVS-AUTH
  Szenario: Ressourcenanfrage mit externem DPoP Key wird vom PEP abgelehnt
    # TA_A_25663_01: Der Authorization Server bindet den ausgegebenen Access Token an den DPoP Key des Token Requests.
    # A_25667: Der PEP HTTP Proxy lehnt den Resource Request ab, wenn Access Token Binding und DPoP Proof nicht übereinstimmen.

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR setze lokale Variable "attackerDpopKey" auf "!{file('src/test/resources/keys/popp-token-server_ecKey.pem')}"

    Wenn TGR setze lokale Variable "dpopCondition" auf ".*${paths.guard.tokenEndpointPath}"
    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "body.jti" auf Wert "attacker-initial-token-jti" mit privatem Schlüssel "${attackerDpopKey}" für Pfad "${dpopCondition}" und 1 Ausführungen und ersetze JWK
    Und TGR lösche aufgezeichnete Nachrichten

    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "${headers.dpop.body.jti}" der mit "attacker-initial-token-jti" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "tokenDpopJwt"
    Und berechne JKT aus DPoP JWT "${tokenDpopJwt}" und speichere in Variable "tokenDpopJkt"
    # @TA_A_25663_01 - Token Binding: cnf.jkt muss mit dem DPoP Public Key Thumbprint des Token Requests übereinstimmen
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.access_token.body.cnf.jkt" überein mit "${tokenDpopJkt}"

    # A_25667 - Resource Request wird abgelehnt, weil der Client nach Reset einen anderen DPoP Key verwendet
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"

  @A_25767
  @A_28963
  @A_26661
  @A_27007
  @TA_A_25767_02
  @TA_A_28963_01
  @TA_A_26661_19
  @TA_A_27007_19
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: DPoP Resource Request - Guard lehnt fremdes JWK (Binding) ab
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"

    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "header.typ" auf Wert "dpop+jwt" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen und ersetze JWK

    # zweites reset, damit der Client beim nächsten Aufruf ein neues DPoP Keypair verwendet
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Dann TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

  @A_25767
  @A_28963
  @TA_A_25767_02
  @TA_A_28963_01
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenario: DPoP Resource Request - Wiederverwendung desselben jti wird abgewiesen
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"

    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"
    Und erzeuge eindeutige DPoP jti und speichere in Variable "resourceReplayJti"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "body.jti" auf Wert "${resourceReplayJti}" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 2 Ausführungen
    Und TGR lösche aufgezeichnete Nachrichten

    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.jti}" überein mit "${resourceReplayJti}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Und TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.body.jti}" überein mit "${resourceReplayJti}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

  @A_25767
  @A_28963
  @TA_A_25767_02
  @TA_A_28963_01
  @dev
  @MASVS-CRYPTO
  @MASVS-AUTH
  Szenariogrundriss: DPoP JWT Manipulation Test - Resource Anfrage
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Und TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"

    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "<JwtField>" auf Wert "<NeuerWert>" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen
    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Vorladen der Nachrichten, damit die nachfolgende Suche nach dem manipulierten Wert schneller durchläuft
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"

    # Finde den manipulierten Request anhand des geänderten Wertes
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.dpop.root}.<JwtField>" der mit "<NeuerWert>" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

    Beispiele: Manipulationen
      | JwtField   | NeuerWert                  |
      | header.typ | JWT                        |
      | header.alg | HS256                      |
      | header.alg | RS999                      |
      | body.iat   | 1600000000                 |
      | body.ath   | wronghash                  |
      | body.htm   | POST                       |
      | body.htu   | https://wrong.url/resource |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft einen DPoP Proof mit Header-Algorithmus none beim Ressourcenzugriff
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalResourceDpopJwt"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    Und erzeuge aus "${originalResourceDpopJwt}" ein DPoP JWT mit Header-Algorithmus none und speichere in Variable "manipulatedDpopJwt"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${manipulatedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.dpop.root}" der mit "${manipulatedDpopJwt}" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.root}" überein mit "${manipulatedDpopJwt}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenariogrundriss: ZETA Guard verwirft einen DPoP Proof ohne Pflicht-Claim beim Ressourcenzugriff
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalResourceDpopJwt"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    Und erzeuge aus "${originalResourceDpopJwt}" ein DPoP JWT ohne Claim "<Claim>" mit privatem Schlüssel "${dpopKey}" und speichere in Variable "manipulatedDpopJwt"
    Und verifiziere ES256 Signatur von DPoP JWT "${manipulatedDpopJwt}"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${manipulatedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.dpop.root}" der mit "${manipulatedDpopJwt}" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.root}" überein mit "${manipulatedDpopJwt}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

    Beispiele: Fehlende Pflicht-Claims
      | Claim |
      | jti   |
      | htm   |
      | htu   |
      | iat   |
      | ath   |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenariogrundriss: ZETA Guard verwirft einen nicht wohlgeformten DPoP Proof beim Ressourcenzugriff (<Variante>)
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR speichere Wert des Knotens "${headers.dpop.root}" der aktuellen Anfrage in der Variable "originalResourceDpopJwt"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    Und erzeuge die JWT-Variante "<Variante>" aus "${originalResourceDpopJwt}" mit privatem Schlüssel "${dpopKey}" und speichere in Variable "malformedDpopJwt"

    Dann Ersetze im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP" durch Wert "${malformedDpopJwt}"
    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.dpop.root}" der mit "${malformedDpopJwt}" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "${headers.dpop.root}" überein mit "${malformedDpopJwt}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

    Beispiele: manipulierte JWT-Varianten
      | Variante                         |
      | invalid_header_json_unquoted_keys  |
      | invalid_payload_json_unquoted_keys |

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft doppelte DPoP Header beim Ressourcenzugriff
    Wenn TGR setze lokale Variable "pathCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    Und Dupliziere im TigerProxy für die Nachricht "${pathCondition}" den Header "DPoP"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}"
    Und prüfe aktuelle Anfrage enthält den Header "DPoP" 2 mal
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

  @A_28963
  @TA_A_28963_01
  @MASVS-CRYPTO
  Szenario: ZETA Guard verwirft einen DPoP Proof mit privatem JWK Anteil beim Ressourcenzugriff
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"

    Dann Setze im TigerProxy für JWT in "${headers.dpop.strict}" das Feld "header.jwk.d" auf Wert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" mit privatem Schlüssel "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen
    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaPath}"
    Und TGR finde die letzte Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.dpop.header.jwk.d}" der mit "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "401"

  @A_27802-02
  @TA_A_27802-02_01
  @TA_A_27802-02_02
  @MASVS-CRYPTO
  Szenariogrundriss:  ZETA Guard Integrationstest, JWT Prüfung
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    # Holen der Keys: Guard Key (signingKey) für Access Token, Client Key (dpopKey) für DPoP
    Und TGR setze lokale Variable "pathCondition" auf ".*${paths.guard.helloZetaPath}"
    Und TGR setze lokale Variable "ecKeyFilePath" auf "${paths.guard.ecKeyFile}"
    Und TGR setze lokale Variable "signingKey" auf "!{file('${ecKeyFilePath}')}"
    Und TGR setze lokale Variable "wrongSigningKey" auf "!{file('src/test/resources/keys/popp-token-server_ecKey.pem')}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    # Client-DPoP-Key vom Storage holen (für ath-Aktualisierung)
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.storage}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.storagePath}"
    Und TGR speichere Wert des Knotens "${body.client.storage.dpop_private_key}" der aktuellen Antwort in der Variable "dpopKey"

    # JWT-Manipulation setzen: Access Token manipulieren UND DPoP ath automatisch aktualisieren
    Dann Setze im TigerProxy für Access Token das Feld "<JwtField>" auf Wert "<NeuerWert>" mit Access Token Key "<AccessTokenKey>" und DPoP Key "${dpopKey}" für Pfad "${pathCondition}" und 1 Ausführungen

    Und TGR lösche aufgezeichnete Nachrichten
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Finde den manipulierten Request anhand des geänderten Wertes
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}" und Knoten "${headers.authorization.dpopToken.root}.<JwtField>" der mit "<NeuerWert>" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "<ResponseCode>"

    Beispiele: Manipulationen (JWT)
      | JwtField   | NeuerWert        | ResponseCode | AccessTokenKey     |
      | header.alg | ES256            | 200          | ${signingKey}      |
      | header.alg | ES256            | 401          | ${wrongSigningKey} |
      | header.alg | RS1              | 401          | ${signingKey}      |
      | header.typ | dpop             | 401          | ${signingKey}      |
      | body.exp   | 1758719276       | 401          | ${signingKey}      |
      | body.aud   | unknown          | 401          | ${signingKey}      |
      | body.iss   | someone          | 401          | ${signingKey}      |
