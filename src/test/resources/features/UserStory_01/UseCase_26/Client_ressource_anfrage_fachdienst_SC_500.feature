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

@UseCase_01_26
Funktionalität: Client_ressource_anfrage_fachdienst_SC_500

  @A_26560
  @A_26661
  @A_26662
  @A_26988
  # US2 @A_26974-01
  @A_27007
  @TA_A_26560_01
  @TA_A_26661_26
  @TA_A_26662_01
  @TA_A_26988_11
  # US2 @TA_A_26974-01_01
  @TA_A_27007_26
  Szenario: PEP HTTP Proxy antwortet mit 500 bei zeta-cause Proxy vom Resource Server
    Gegeben sei TGR sende eine leere GET Anfrage an "${paths.client.reset}"

    Wenn TGR sende eine leere GET Anfrage an "${paths.client.helloZetaProxyError}"

    # TA_A_26560_01: Request NACH PEP - Pfad wurde gemäß Weiterleitungskonfiguration transformiert
    Und TGR finde die letzte Anfrage mit dem Pfad "^${paths.fachdienst.helloZetaProxyErrorPath}$"
    Und TGR prüfe aktueller Request stimmt im Knoten "$.path" überein mit "${paths.fachdienst.helloZetaProxyErrorPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "500"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "${headers.zeta.cause}" überein mit "Proxy"
    # US2 Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "errorBody"

    # TA_A_26560_01: Request-Weiterleitung gemäß URL-Konfiguration vor PEP
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.guard.helloZetaProxyErrorPath}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "500"
    # US2 Und TGR prüfe aktuelle Antwort enthält nicht Knoten "${headers.zeta.cause}"
    Und TGR speichere Wert des Knotens "$.body" der aktuellen Antwort in der Variable "body"
    Und validiere "${body}" gegen Schema "schemas/v_1_0/zeta-error.yaml"
    # US2 Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.body" nicht überein mit ".*${errorBody}.*"

    # Warte auf Telemetrie-Ingestion (Lieferintervall standardmäßig 60s)
    Und warte "${testdata.telemetry_wait_seconds}" Sekunden

    # TA_A_26988_11 - Resource Server: Fehlermeldung wird vom Telemetriedaten Service gesammelt und ist in OpenSearch auffindbar.
    Wenn TGR sende eine GET Anfrage an "${paths.openSearch.baseUrl}${paths.openSearch.openTelemetryLogsSearchPath}" mit folgenden Daten:
      | q                                                                                                                                                                                                                                                                                                                          | size |
      | resource.k8s.namespace.name:${zeta_k8s_namespace} AND resource.k8s.container.name:${telemetry.service.telemetryDataService} AND resource.service.name:"${telemetry.service.resourceServer}" AND body:${paths.fachdienst.helloZetaProxyErrorPath} AND body:500 AND severity.number:[13 TO *] AND @timestamp:[now-3m TO now] | 1    |
    Dann TGR finde die letzte Anfrage mit dem Pfad "${paths.openSearch.openTelemetryLogsSearchPathPattern}"
    Und TGR prüfe aktuelle Antwort stimmt im Knoten "$.responseCode" überein mit "200"
    Und TGR prüfe aktuelle Antwort enthält Knoten "$.body.hits.hits.0"
