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

@UseCase_01_15
Funktionalität: client_ressource_anfrage_fachdienst_sc_400

  @A_26477
  @A_26661
  @A_26988
  @A_27007
  @TA_A_26477_04
  @TA_A_26661_18
  @TA_A_26988_01
  @TA_A_26988_02
  @TA_A_26988_03
  @TA_A_27007_18
  @MASVS-AUTH
  Szenario: Fehlender PoPP-Header bei Ressource-Anfrage
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"
    Und TGR setze lokale Variable "poppHeaderCondition" auf "isRequest && request.path =~ '.*${paths.guard.helloZetaPath}'"
    Und Setze im TigerProxy für die Nachricht "${poppHeaderCondition}" die Regex-Manipulation auf Feld "$.header" mit Regex "${headers.popp.lineRegex}" und Wert ""
    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZeta}"
    Dann TGR finde die erste Anfrage mit Pfad "${paths.guard.helloZetaPath}"
    Und TGR prüfe aktueller Request enthält nicht Knoten "${headers.popp.root}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "400"

    # Warte auf Telemetrie-Ingestion (Lieferintervall standardmäßig 60s)
    Und warte "${testdata.telemetry_wait_seconds}" Sekunden

    # TA_A_26988_01 - Ingress: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                                                    | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.ingress}" AND body:${paths.guard.helloZetaPath} AND body:400 AND severity.number:[13 TO *] AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

    # TA_A_26988_02 - Egress: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                                                   | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.egress}" AND body:${paths.guard.helloZetaPath} AND body:400 AND severity.number:[13 TO *] AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"

    # TA_A_26988_03 - HTTP Proxy: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                        | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.httpProxy}" AND body:${paths.guard.helloZetaPath} AND body:400 AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"
