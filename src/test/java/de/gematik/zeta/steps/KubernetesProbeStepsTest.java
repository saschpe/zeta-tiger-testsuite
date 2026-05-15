/*
 * #%L
 * ZETA Testsuite
 * %%
 * (C) achelos GmbH, 2025, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

package de.gematik.zeta.steps;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for OpenTelemetry Collector relay configuration matching.
 */
class KubernetesProbeStepsTest {

  /**
   * Verifies that a standard OTLP gRPC exporter referenced by traces is detected with a batch processor.
   */
  @Test
  void parseCollectorRelayConfigDetectsTraceBatchAndOtlpGrpcExporter() {
    var relayConfig = """
        receivers:
          otlp:
            protocols:
              grpc: {}
        processors:
          batch: {}
        exporters:
          otlp:
            endpoint: otel-collector:4317
        service:
          pipelines:
            traces:
              receivers:
                - otlp
              processors:
                - batch
              exporters:
                - otlp
        """;

    assertThat(KubernetesProbeSteps.tracesPipelineUsesBatch(relayConfig)).isTrue();
    assertThat(KubernetesProbeSteps.firstTraceOtlpExporter(relayConfig)).contains("otlp");
    assertThat(KubernetesProbeSteps.configuredOtlpExporters(relayConfig)).containsExactly("otlp");
    assertThat(KubernetesProbeSteps.activeOtlpForwardingProtocols(relayConfig)).containsExactly("OTLP/gRPC");
    assertThat(KubernetesProbeSteps.pipelinesUsingAnyExporter(relayConfig, List.of("otlp"))).containsExactly("traces");
    assertThat(KubernetesProbeSteps.tracePipelineForReport(relayConfig)).contains("processors:", "- batch", "- otlp");
  }

  /**
   * Verifies that an OTLP HTTP/JSON exporter referenced by traces is detected.
   */
  @Test
  void relayConfigMatchingDetectsOtlpHttpJsonExporter() {
    var relayConfig = """
        exporters:
          debug: {}
          otlphttp/main:
            endpoint: https://collector.example.test/v1/traces
            encoding: json
        processors:
          batch/main:
            timeout: 1s
        service:
          pipelines:
            logs:
              exporters:
                - debug
            traces:
              processors:
                - batch
              exporters:
                - debug
                - otlphttp/main
        """;

    assertThat(KubernetesProbeSteps.tracesPipelineUsesBatch(relayConfig)).isTrue();
    assertThat(KubernetesProbeSteps.firstTraceOtlpExporter(relayConfig)).contains("otlphttp/main");
    assertThat(KubernetesProbeSteps.configuredOtlpExporters(relayConfig)).containsExactly("otlphttp/main");
    assertThat(KubernetesProbeSteps.activeOtlpForwardingProtocols(relayConfig)).containsExactly("OTLP/HTTP JSON");
    assertThat(KubernetesProbeSteps.pipelinesUsingAnyExporter(relayConfig, List.of("otlphttp/main")))
        .containsExactly("traces");
  }

  /**
   * Verifies that OTLP HTTP exporters without JSON encoding do not satisfy the allowed HTTP/JSON protocol check.
   */
  @Test
  void relayConfigMatchingDoesNotReportOtlpHttpWithoutJsonEncodingAsAllowedProtocol() {
    var relayConfig = """
        exporters:
          otlp_http/test-monitoring-service:
            endpoint: http://test-monitoring-collector-local:4318
        service:
          pipelines:
            logs:
              exporters:
                - otlp_http/test-monitoring-service
        """;

    assertThat(KubernetesProbeSteps.configuredOtlpExporters(relayConfig))
        .containsExactly("otlp_http/test-monitoring-service");
    assertThat(KubernetesProbeSteps.activeOtlpForwardingProtocols(relayConfig)).isEmpty();
    assertThat(KubernetesProbeSteps.pipelinesUsingAnyExporter(
        relayConfig, List.of("otlp_http/test-monitoring-service"))).containsExactly("logs");
  }

  /**
   * Verifies that configured OTLP exporters do not count unless a service pipeline references them.
   */
  @Test
  void relayConfigMatchingDoesNotReportUnusedOtlpExporter() {
    var relayConfig = """
        exporters:
          otlp/unused:
            endpoint: otel-collector:4317
          debug: {}
        service:
          pipelines:
            traces:
              processors:
                - memory_limiter
              exporters:
                - debug
        """;

    assertThat(KubernetesProbeSteps.tracesPipelineUsesBatch(relayConfig)).isFalse();
    assertThat(KubernetesProbeSteps.firstTraceOtlpExporter(relayConfig)).isEmpty();
    assertThat(KubernetesProbeSteps.configuredOtlpExporters(relayConfig)).containsExactly("otlp/unused");
    assertThat(KubernetesProbeSteps.activeOtlpForwardingProtocols(relayConfig)).isEmpty();
    assertThat(KubernetesProbeSteps.pipelinesUsingAnyExporter(relayConfig, List.of("otlp/unused"))).isEmpty();
  }

  /**
   * Verifies that missing traces pipelines are rendered with a report placeholder.
   */
  @Test
  void relayConfigMatchingReportsMissingTracePipeline() {
    assertThat(KubernetesProbeSteps.tracePipelineForReport("service:\n  pipelines: {}\n"))
        .isEqualTo("<pipeline not found>");
  }
}
