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

@UseCase_01_24
Funktionalität: Client_ressource_anfrage_Performance_SC_200

  @A_26486-01
  @A_26488
  @TA_A_26486-01_01
  @TA_A_26488_01
  @dev
  @no_proxy
  @performance
  @websocket
  Szenario: PEP HTTP Proxy - Performance und Last ohne ASL
    # Voraussetzung derzeit: ASL ist vor dem Lauf manuell deaktiviert.
    # Gemessen wird HTTP-Last auf /hellozeta; die 300 WebSocket-Verbindungen bleiben parallel offen.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "300"
    Und TGR setze lokale Variable "jtargetRps" auf "310"
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Wenn 301 WebSocket Verbindungen zu "${paths.client.websocketBaseUrl}" aufgebaut werden
    Dann sind mindestens 301 WebSocket Verbindungen offen
    Wenn JMeter mit dem Plan "parameterized-http-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL          | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE            | /load/{id}{proxyPath}                                  |
      | -JLOAD_INIT_PATH_TEMPLATE       | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH               | /hellozeta                                             |
      | -JLOAD_INSTANCE_COUNT           | 300                                                    |
      | -JLOAD_CREATE_BATCH_SIZE        | 100                                                    |
      | -JLOAD_ONE_INSTANCE_PER_THREAD  | true                                                   |
      | -JLOAD_AUTO_INIT                | true                                                   |
      | -JLOAD_INIT_FLOW                | authenticate                                           |
      | -JLOAD_WAIT_READY               | true                                                   |
      | -JLOAD_READY_TIMEOUT_S          | 180                                                    |
      | -JLOAD_CREATE_BODY_INLINE       | true                                                   |
      | -JLOAD_FACHDIENST_URL           | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST   | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JLOAD_POPP_TOKEN_GENERATOR_URL | ${popp_token_generator_url}                            |
      | -JHTTP_METHOD                   | GET                                                    |
      | -JDURATION_S                    | ${jdurationS}                                          |
      | -JRAMP_S                        | 10                                                     |
      | -JTHREADS                       | 300                                                    |
      | -JTARGET_RPS                    | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS               | 30                                                     |
      | -JLOAD_INIT_BUFFER_TARGET_VAR   | prometheusInitBufferS                                  |
      | -l                              | out/pep-performance-without-asl.jtl                    |
      | -f                              |                                                        |

    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die Rate >= "300" pro Sekunde ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Spans "${telemetry.spanGroup.httpProxy.pepAndWellKnown}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 7.5 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 10 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 15 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 100 ms ist
    Und sind mindestens 301 WebSocket Verbindungen offen
    Und werden alle aufgebauten WebSocket Verbindungen geschlossen

  @A_26486-01
  @A_26488
  @TA_A_26486-01_01
  @TA_A_26488_01
  @no_proxy
  @performance
  @websocket
  Szenario: PEP HTTP Proxy - Performance mit ASL
    # Voraussetzung derzeit: ASL ist vor dem Lauf manuell aktiviert.
    # Der fachliche Lastpfad bleibt /hellozeta; zusätzlich werden interne /ASL-Spans auf Latenz geprüft.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "60"
    Und TGR setze lokale Variable "jtargetRps" auf "310"
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Wenn 301 WebSocket Verbindungen zu "${paths.client.websocketBaseUrl}" aufgebaut werden
    Dann sind mindestens 301 WebSocket Verbindungen offen
    Wenn JMeter mit dem Plan "parameterized-http-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL          | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE            | /load/{id}{proxyPath}                                  |
      | -JLOAD_INIT_PATH_TEMPLATE       | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH               | /hellozeta                                             |
      | -JLOAD_INSTANCE_COUNT           | 300                                                    |
      | -JLOAD_CREATE_BATCH_SIZE        | 100                                                    |
      | -JLOAD_ONE_INSTANCE_PER_THREAD  | true                                                   |
      | -JLOAD_AUTO_INIT                | true                                                   |
      | -JLOAD_INIT_FLOW                | authenticate                                           |
      | -JLOAD_WAIT_READY               | true                                                   |
      | -JLOAD_READY_TIMEOUT_S          | 180                                                    |
      | -JLOAD_CREATE_BODY_INLINE       | true                                                   |
      | -JLOAD_FACHDIENST_URL           | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST   | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JLOAD_POPP_TOKEN_GENERATOR_URL | ${popp_token_generator_url}                            |
      | -JHTTP_METHOD                   | GET                                                    |
      | -JDURATION_S                    | ${jdurationS}                                          |
      | -JRAMP_S                        | 10                                                     |
      | -JTHREADS                       | 300                                                    |
      | -JTARGET_RPS                    | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS               | 30                                                     |
      | -JLOAD_INIT_BUFFER_TARGET_VAR   | prometheusInitBufferS                                  |
      | -l                              | out/pep-performance-with-asl.jtl                       |
      | -f                              |                                                        |

    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die Rate >= "300" pro Sekunde ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Spans "${telemetry.spanGroup.httpProxy.aslPepAndWellKnown}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 7.5 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 10 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 15 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 100 ms ist

    Und sind mindestens 301 WebSocket Verbindungen offen
    Und werden alle aufgebauten WebSocket Verbindungen geschlossen

  @A_26489-01
  @A_26491
  @TA_A_26489-01_01
  @TA_A_26491_01
  @no_proxy
  @performance
  Szenario: PDP Authorization Server - Last und Performance
    # 150 Instanzen, je einem Thread fest zugeordnet (ONE_INSTANCE_PER_THREAD=true).
    # AUTO_INIT bereitet die Instanzen im Load Driver einmalig vor; zusätzlich ruft der konfigurierte
    # Init-Flow /authenticate pro Instanz vor dem Messlauf genau einmal auf.
    # Load-Loop: removeAuth → authenticate → removeAuth → authenticate → ...
    # removeAuth läuft bewusst vor dem gemessenen authenticate, damit der nächste authenticate
    # wieder nonce + token auslöst, ohne den Load-Driver-Setup-Pfad aufzugeben.
    # TARGET_RPS=150 bezieht sich auf den JMeter-Step "PDP Authenticate"; A_26491 wird daher über
    # die kombinierte Prometheus-Rate nonce + token und nicht über die rohe JMeter-Requestzahl bewertet.
    # AFO A_26491: Summe nonce + token >= 300 req/s über alle PDP-Endpunkte.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "300"
    Und TGR setze lokale Variable "jtargetRps" auf "160"
    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Wenn JMeter mit dem Plan "pdp-auth-cycle-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL         | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE           | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_INIT_PATH_TEMPLATE      | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH              | /authenticate                                          |
      | -JLOAD_INSTANCE_COUNT          | 160                                                    |
      | -JLOAD_CREATE_BATCH_SIZE       | 100                                                    |
      | -JLOAD_ONE_INSTANCE_PER_THREAD | true                                                   |
      | -JLOAD_AUTO_INIT               | true                                                   |
      | -JLOAD_INIT_FLOW               | authenticate                                           |
      | -JLOAD_WAIT_READY              | true                                                   |
      | -JLOAD_READY_TIMEOUT_S         | 180                                                    |
      | -JLOAD_CREATE_BODY_INLINE      | true                                                   |
      | -JLOAD_FACHDIENST_URL          | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST  | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JDURATION_S                   | ${jdurationS}                                          |
      | -JRAMP_S                       | 10                                                     |
      | -JTHREADS                      | 160                                                    |
      | -JTARGET_RPS                   | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS              | 30                                                     |
      | -JLOAD_INIT_BUFFER_TARGET_VAR  | prometheusInitBufferS                                  |
      | -l                             | out/pdp-performance.jtl                                |
      | -f                             |                                                        |

    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    # AFO A_26491: nach dem Lastlauf festen Collector-Delay abwarten; das größere Fenster enthält
    # auch verzögert exportierte Span-Metriken, die Rate bleibt aber auf die eigentliche Lastdauer normiert
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceAndToken}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die kombinierte Rate >= "300" pro Sekunde ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceAndToken}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    # PDP /token: interne Keycloak-Latenz für Token-Exchange
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    # PDP /nonce: interne Keycloak-Latenz für Nonce-Erzeugung
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist

  @no_proxy
  @performance
  @require_kubectl
  @deployment_modification
  @A_26487
  @TA_A_26487_01
  Szenariogrundriss: PEP HTTP Proxy - horizontale Skalierbarkeit mit mindestens 75 Prozent zusätzlicher Leistung pro Pod
    # Feste Basis: 300 RPS mit einem Pod.
    # Für jede zusätzliche Replica werden mindestens weitere 225 RPS gefordert.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "60"
    Und TGR setze lokale Variable "pepBaseRps" auf "310"
    Und berechne und setze lokale Variable "jtargetRps" aus Basis "${pepBaseRps}" und <replicas> Replikas mit 75 Prozent Zusatzleistung pro Pod
    Und berechne und setze lokale Variable "pepConcurrency" aus Basis "${pepBaseRps}" und <replicas> Replikas mit 75 Prozent Zusatzleistung pro Pod
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Und skaliere das Deployment "${zetaDeploymentConfig.pep.podName}" auf <replicas> Replikas
    Wenn JMeter mit dem Plan "parameterized-http-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL          | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE            | /load/{id}{proxyPath}                                  |
      | -JLOAD_INIT_PATH_TEMPLATE       | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH               | /hellozeta                                             |
      | -JLOAD_INSTANCE_COUNT           | ${pepConcurrency}                                      |
      | -JLOAD_CREATE_BATCH_SIZE        | 100                                                    |
      | -JLOAD_ONE_INSTANCE_PER_THREAD  | true                                                   |
      | -JLOAD_AUTO_INIT                | true                                                   |
      | -JLOAD_INIT_FLOW                | authenticate                                           |
      | -JLOAD_WAIT_READY               | true                                                   |
      | -JLOAD_READY_TIMEOUT_S          | 180                                                    |
      | -JLOAD_CREATE_BODY_INLINE       | true                                                   |
      | -JLOAD_FACHDIENST_URL           | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST   | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JLOAD_POPP_TOKEN_GENERATOR_URL | ${popp_token_generator_url}                            |
      | -JHTTP_METHOD                   | GET                                                    |
      | -JDURATION_S                    | ${jdurationS}                                          |
      | -JRAMP_S                        | 10                                                     |
      | -JTHREADS                       | ${pepConcurrency}                                      |
      | -JTARGET_RPS                    | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS               | 30                                                     |
      | -JLOAD_INIT_BUFFER_TARGET_VAR   | prometheusInitBufferS                                  |
      | -l                              | out/pep-scalability-<replicas>-pods.jtl                |
      | -f                              |                                                        |

    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die Rate >= "${jtargetRps}" pro Sekunde ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Spans "${telemetry.spanGroup.httpProxy.aslPepAndWellKnown}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 7.5 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 10 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 15 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 100 ms ist

    Beispiele:
      | replicas |
      | 1        |
      | 2        |
      | 3        |
      | 4        |
      | 5        |

  @no_proxy
  @performance
  @require_kubectl
  @deployment_modification
  @A_26490
  @TA_A_26490_01
  Szenariogrundriss: PDP Authorization Server - horizontale Skalierbarkeit mit mindestens 75 Prozent zusätzlicher Leistung pro Pod
    # Feste Basis: kombinierte PDP-Rate nonce + token >= 300/s mit einem Pod.
    # Für jede zusätzliche Replica werden mindestens weitere 225/s gefordert.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "60"
    Und TGR setze lokale Variable "pdpBaseAuthenticateRps" auf "160"
    Und TGR setze lokale Variable "pdpBaseCombinedRps" auf "300"
    Und berechne und setze lokale Variable "jtargetRps" aus Basis "${pdpBaseAuthenticateRps}" und <replicas> Replikas mit 75 Prozent Zusatzleistung pro Pod
    Und berechne und setze lokale Variable "expectedCombinedRps" aus Basis "${pdpBaseCombinedRps}" und <replicas> Replikas mit 75 Prozent Zusatzleistung pro Pod
    Und berechne und setze lokale Variable "pdpConcurrency" aus Basis "${pdpBaseAuthenticateRps}" und <replicas> Replikas mit 75 Prozent Zusatzleistung pro Pod
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Und skaliere das Deployment "${zetaDeploymentConfig.authserver.podName}" auf <replicas> Replikas
    Wenn JMeter mit dem Plan "pdp-auth-cycle-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL         | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE           | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_INIT_PATH_TEMPLATE      | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH              | /authenticate                                          |
      | -JLOAD_INSTANCE_COUNT          | ${pdpConcurrency}                                      |
      | -JLOAD_CREATE_BATCH_SIZE       | 100                                                    |
      | -JLOAD_ONE_INSTANCE_PER_THREAD | true                                                   |
      | -JLOAD_AUTO_INIT               | true                                                   |
      | -JLOAD_INIT_FLOW               | authenticate                                           |
      | -JLOAD_WAIT_READY              | true                                                   |
      | -JLOAD_READY_TIMEOUT_S         | 180                                                    |
      | -JLOAD_CREATE_BODY_INLINE      | true                                                   |
      | -JLOAD_FACHDIENST_URL          | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST  | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JDURATION_S                   | ${jdurationS}                                          |
      | -JRAMP_S                       | 10                                                     |
      | -JTHREADS                      | ${pdpConcurrency}                                      |
      | -JTARGET_RPS                   | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS              | 30                                                     |
      | -l                             | out/pdp-scalability-<replicas>-pods.jtl                |
      | -f                             |                                                        |

    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceAndToken}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die kombinierte Rate >= "${expectedCombinedRps}" pro Sekunde ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceAndToken}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist

    Beispiele:
      | replicas |
      | 1        |
      | 2        |
      | 3        |
      | 4        |
      | 5        |

  @A_26486-01
  @A_26488
  @A_26489-01
  @A_26491
  @TA_A_26486-01_01
  @TA_A_26488_01
  @TA_A_26489-01_01
  @TA_A_26491_01
  @no_proxy
  @dev
  @performance
  @websocket
  Szenario: PDP und PEP kombiniert - Realistischer Langzeittest mit Client-Rotation
    # Kombiniertes PEP+PDP-Lastszenario mit Client-Rotation.
    # 70000 Instanzen werden angelegt; 180 Threads rotieren reihum über alle 70000 Instanzen
    # (ONE_INSTANCE_PER_THREAD=false), sodass jede Instanz im Laufe des Tests bedient wird.
    # Das erste /hellozeta auf einer noch nicht initialisierten Instanz löst Discovery-, Nonce-,
    # Register- und Token-Schritte aus und erzeugt dadurch zusätzliche PDP- und Well-known-Last.
    Gegeben sei TGR lösche aufgezeichnete Nachrichten
    Und TGR setze lokale Variable "jdurationS" auf "600"
    Und TGR setze lokale Variable "jtargetRps" auf "310"
    Und TGR setze lokale Variable "prometheusInitBufferS" auf "180"
    Und TGR setze lokale Variable "prometheusCollectorDelayS" auf "${testdata.telemetry_wait_seconds}"
    Wenn 300 WebSocket Verbindungen zu "${paths.client.websocketBaseUrl}" aufgebaut werden
    Dann sind mindestens 300 WebSocket Verbindungen offen
    Wenn JMeter mit dem Plan "parameterized-http-test" gestartet wird
      | -JLOAD_DRIVER_BASE_URL          | https://${zeta_base_url}                               |
      | -JLOAD_PATH_TEMPLATE            | /load/{id}{proxyPath}                                  |
      | -JLOAD_INIT_PATH_TEMPLATE       | /loaddriver-api/{id}{proxyPath}                        |
      | -JLOAD_PROXY_PATH               | /hellozeta                                             |
      | -JLOAD_INSTANCE_COUNT           | 70000                                                  |
      | -JLOAD_CREATE_BATCH_SIZE        | 4000                                                   |
      | -JLOAD_ONE_INSTANCE_PER_THREAD  | false                                                  |
      | -JLOAD_AUTO_INIT                | false                                                  |
      | -JLOAD_PRECHECK_ENABLED         | false                                                  |
      | -JLOAD_CREATE_BODY_INLINE       | true                                                   |
      | -JLOAD_FACHDIENST_URL           | https://${zeta_base_url}/pep/achelos_testfachdienst/   |
      | -JLOAD_SMCB_KEYSTORE_MANIFEST   | ${testCertificates.dir}/manifest/keystore-manifest.tsv |
      | -JLOAD_POPP_TOKEN_GENERATOR_URL | ${popp_token_generator_url}                            |
      | -JHTTP_METHOD                   | GET                                                    |
      | -JDURATION_S                    | ${jdurationS}                                          |
      | -JRAMP_S                        | 10                                                     |
      | -JTHREADS                       | 180                                                    |
      | -JTARGET_RPS                    | ${jtargetRps}                                          |
      | -JJITTER_RANGE_MS               | 30                                                     |
      | -JLOAD_INIT_BUFFER_TARGET_VAR   | prometheusInitBufferS                                  |
      | -l                              | out/pdp-pep-rotation-performance.jtl                   |
      | -f                              |                                                        |

    Und TGR setze lokale Variable "prometheusWindowS" auf "!{${jdurationS} + 2*${prometheusCollectorDelayS} + ${prometheusInitBufferS}}"
    Und warte "${prometheusCollectorDelayS}" Sekunden
    # AFO A_26491: kombinierte PDP-Rate nonce + register + token >= 300/s über alle kalten Clients
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceRegisterAndToken}", Fenster "${prometheusWindowS}" Sekunden und Divisor "${jdurationS}" Sekunden die kombinierte Rate >= "300" pro Sekunde ist
    # PEP: ASL-Latenz (Authorization Session Layer)
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Spans "${telemetry.spanGroup.httpProxy.aslPepAndWellKnown}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.asl}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    # PEP: interne nginx-Latenz
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.pep}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    # Well-known: Discovery-Requests werden im Rotationsszenario durch re-initialisierte Clients erneut ausgelöst
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 7.5 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 10 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 15 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.httpProxy}", Span "${telemetry.span.httpProxy.wellKnown}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 100 ms ist
    # PDP /nonce: interne Keycloak-Latenz für Nonce-Erzeugung
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Spans "${telemetry.spanGroup.authorizationServer.nonceRegisterAndToken}", Fenster "${prometheusWindowS}" Sekunden die kombinierte Fehlerrate <= "1.0" Prozent ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.nonce}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    # PDP /register: Latenz für Client-Registrierung in Keycloak
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.clientRegistration}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.clientRegistration}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.clientRegistration}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.clientRegistration}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    # PDP /token: Latenz für Token-Exchange in Keycloak
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der avg-Wert <= 75 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p90-Wert <= 100 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p95-Wert <= 150 ms ist
    Und stelle sicher, dass in Prometheus für Service "${telemetry.service.authorizationServer}", Span "${telemetry.span.authorizationServer.token}", Fenster "${prometheusWindowS}" Sekunden der p99-Wert <= 1000 ms ist
    Und sind mindestens 300 WebSocket Verbindungen offen
    Und werden alle aufgebauten WebSocket Verbindungen geschlossen
    
