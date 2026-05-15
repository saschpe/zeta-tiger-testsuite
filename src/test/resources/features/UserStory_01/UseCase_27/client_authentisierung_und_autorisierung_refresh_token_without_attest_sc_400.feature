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

@UseCase_01_27
Funktionalität: client_authentisierung_und_autorisierung_refresh_token_without_attest_sc_400

  @A_25662
  @A_25782
  @A_26662
  @TA_A_25662_02
  @TA_A_25782_05
  @TA_A_26662_01
  @MASVS-AUTH
  Szenario: Refresh Token Reuse wird vom Authorization Server abgelehnt (Negativtest)
    # expires_in Manipulation aktivieren BEVOR der erste HelloZeta Request
    # (3 Ausführungen: Initial Token Exchange + 1. Refresh + 2. Refresh, alle mit manipuliertem expires_in)
    Wenn TGR setze lokale Variable "opaCondition" auf "isResponse && request.path =~ '.*${paths.opa.decisionPath}'"
    Dann Setze im TigerProxy für die Nachricht "${opaCondition}" die Manipulation auf Feld "$.body.result.ttl.access_token" und Wert "${accessTokenTtl}" und 3 Ausführungen
    Wenn TGR setze lokale Variable "condition" auf "isResponse && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Dann Setze im TigerProxy für die Nachricht "${condition}" die Manipulation auf Feld "$.body.expires_in" und Wert "${accessTokenTtl}" und 3 Ausführungen

    Und TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"

    # Warten dass HelloZeta-Response vollständig geparst ist
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # Refresh Token aus dem Token Exchange speichern
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.tokenEndpointPath}"
    Und TGR speichere Wert des Knotens "$.body.refresh_token" der aktuellen Antwort in der Variable "usedRefreshToken"

    # Nachrichten löschen damit wir nach dem Refresh nur den Refresh-Request finden
    Und TGR lösche aufgezeichnete Nachrichten

    # Warte bis Access Token abgelaufen ist
    Und warte "${accessTokenTtl}" Sekunden

    # Ersten Refresh durchführen (verwendet usedRefreshToken)
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"

    # Verifiziere dass der Refresh mit dem gespeicherten Token erfolgte (jetzt einziger Token Request)
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "refresh_token" übereinstimmt
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.refresh_token" überein mit "${usedRefreshToken}"

    # Versuche das bereits verwendete Refresh Token nochmal zu verwenden
    # Manipuliere den Request, um das alte Refresh Token zurückzuspielen
    # Hinweis: Token Request Body ist application/x-www-form-urlencoded (Form-Data), nicht JSON
    # TigerProxy hat keinen RbelHttpFormDataWriter, daher muss Regex auf $.body verwendet werden
    Wenn TGR setze lokale Variable "replayCondition" auf "isRequest && request.path =~ '.*${paths.guard.tokenEndpointPath}'"
    Dann Setze im TigerProxy für die Nachricht "${replayCondition}" die Regex-Manipulation auf Feld "$.body" mit Regex "refresh_token=[^&]*" und Wert "refresh_token=${usedRefreshToken}"

    Und TGR lösche aufgezeichnete Nachrichten

    # Zweiter Refresh-Versuch sollte fehlschlagen
    Und warte "${accessTokenTtl}" Sekunden
    Und TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.client.helloZetaPath}"

    # Finde den Refresh Token Request (nicht den Token Exchange der danach folgt)
    # Wir suchen explizit nach dem Request mit grant_type=refresh_token
    Dann TGR finde die letzte Anfrage mit Pfad "${paths.guard.tokenEndpointPath}" und Knoten "$.body.grant_type" der mit "refresh_token" übereinstimmt
    Und TGR prüfe aktueller Request stimmt im Knoten "$.body.refresh_token" überein mit "${usedRefreshToken}"

    # Erwarte invalid_grant
    # Grund: Refresh Token wurde bereits verwendet (Rotation-Verletzung)
    # Die Response zu diesem Request sollte 400 mit invalid_grant sein
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.error"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body.error" überein mit "invalid_grant"
    # Zusätzliche Schema-Validierung
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "errorBody"
    Und validiere "${errorBody}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
