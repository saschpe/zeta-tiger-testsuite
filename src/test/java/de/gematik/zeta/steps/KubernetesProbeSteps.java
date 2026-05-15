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

import com.fasterxml.jackson.databind.JsonNode;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.lib.reports.SerenityReportUtils;
import de.gematik.zeta.services.ZetaDeploymentConfigurationService;
import de.gematik.zeta.services.ZetaDeploymentConfigurationServiceFactory;
import io.cucumber.java.de.Und;
import io.cucumber.java.en.And;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Cucumber step definitions for Kubernetes probe verification.
 */
public class KubernetesProbeSteps {

  private static final String ZETA_NAMESPACE_CONFIG_KEY = "zetaDeploymentConfig.namespace";
  private static final String OPENTELEMETRY_RELAY_JSONPATH = "jsonpath={.data.relay}";
  private static final String TELEMETRY_GATEWAY_CONFIGMAP_SELECTOR =
      "app.kubernetes.io/name=telemetry-gateway,app.kubernetes.io/component=standalone-collector";
  private static final Pattern TRACES_PIPELINE_USES_BATCH = Pattern.compile(
      "(?ms)^\\s*traces:\\s*$.*?^\\s*processors:\\s*$.*?^\\s*-\\s*batch\\s*(?:#.*)?$");
  private static final Pattern TRACES_PIPELINE_OTLP_EXPORTER = Pattern.compile(
      "(?ms)^\\s*traces:\\s*$.*?^\\s*exporters:\\s*$.*?^\\s*-\\s*(otlp[\\w-]*(?:/[^\\s#]+)?)\\s*(?:#.*)?$");
  private static final Pattern TRACES_PIPELINE_PATTERN = Pattern.compile(
      "(?ms)^\\s*traces:\\s*$.*?(?=^\\s{0,4}\\S|\\z)");
  private static final List<String> TELEMETRY_SIGNALS = List.of("logs", "metrics", "traces");

  private final ZetaDeploymentConfigurationService service = ZetaDeploymentConfigurationServiceFactory.getInstance();

  /**
   * Checks whether the traces pipeline uses a batch processor.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return true if the traces pipeline references the batch processor
   */
  static boolean tracesPipelineUsesBatch(String relayConfig) {
    return TRACES_PIPELINE_USES_BATCH.matcher(relayConfig).find();
  }

  /**
   * Reads the first OTLP exporter from the traces pipeline.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return OTLP exporter name when present
   */
  static Optional<String> firstTraceOtlpExporter(String relayConfig) {
    var exporterMatcher = TRACES_PIPELINE_OTLP_EXPORTER.matcher(relayConfig);
    if (exporterMatcher.find()) {
      return Optional.of(exporterMatcher.group(1));
    }
    return Optional.empty();
  }

  /**
   * Extracts the traces pipeline for the Serenity report.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return traces pipeline block or a placeholder
   */
  static String tracePipelineForReport(String relayConfig) {
    var tracesMatcher = TRACES_PIPELINE_PATTERN.matcher(relayConfig);
    var tracesPipeline = "";
    while (tracesMatcher.find()) {
      tracesPipeline = tracesMatcher.group();
    }
    if (tracesPipeline.isBlank()) {
      return "<pipeline not found>";
    }
    return tracesPipeline.stripTrailing();
  }

  /**
   * Reads configured OTLP gRPC or HTTP/JSON exporter names from the collector configuration.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return exporter names
   */
  static List<String> configuredOtlpExporters(String relayConfig) {
    return exporterNames(firstBlock(relayConfig, "exporters", 0)).stream()
        .filter(KubernetesProbeSteps::isOtlpExporterName)
        .toList();
  }

  /**
   * Reads active OTLP forwarding protocols from the collector service pipelines.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return active OTLP forwarding protocols
   */
  static List<String> activeOtlpForwardingProtocols(String relayConfig) {
    var exportersBlock = firstBlock(relayConfig, "exporters", 0);
    return configuredOtlpExporters(relayConfig).stream()
        .filter(exporterName -> !pipelinesUsingAnyExporter(relayConfig, List.of(exporterName)).isEmpty())
        .map(exporterName -> otlpProtocolForExporter(exportersBlock, exporterName))
        .flatMap(Optional::stream)
        .distinct()
        .toList();
  }

  /**
   * Checks which service pipelines reference any of the provided exporters.
   *
   * @param relayConfig   OpenTelemetry Collector relay configuration
   * @param exporterNames exporter names to search
   * @return pipeline signal names
   */
  static List<String> pipelinesUsingAnyExporter(String relayConfig, List<String> exporterNames) {
    if (exporterNames.isEmpty()) {
      return List.of();
    }

    var serviceBlock = firstBlock(relayConfig, "service", 0);
    var pipelinesBlock = firstBlock(serviceBlock, "pipelines", 2);
    return TELEMETRY_SIGNALS.stream()
        .filter(signal -> pipelineUsesAnyExporter(pipelinesBlock, signal, exporterNames))
        .toList();
  }

  /**
   * Checks whether a service pipeline references any of the given exporters.
   *
   * @param pipelinesBlock collector service pipelines block
   * @param signal         pipeline signal name
   * @param exporterNames  exporter names to search
   * @return true if the pipeline references one of the exporters
   */
  private static boolean pipelineUsesAnyExporter(String pipelinesBlock, String signal, List<String> exporterNames) {
    var signalBlock = firstBlock(pipelinesBlock, signal, 4);
    var exportersBlock = firstBlock(signalBlock, "exporters", 6);
    var references = listItems(exportersBlock);
    return references.stream().anyMatch(exporterNames::contains);
  }

  /**
   * Extracts the service pipelines block for the Serenity report.
   *
   * @param relayConfig OpenTelemetry Collector relay configuration
   * @return service pipelines block or a placeholder
   */
  static String servicePipelinesForReport(String relayConfig) {
    var serviceBlock = firstBlock(relayConfig, "service", 0);
    var pipelinesBlock = firstBlock(serviceBlock, "pipelines", 2);
    if (pipelinesBlock.isBlank()) {
      return "<pipelines not found>";
    }
    return pipelinesBlock.stripTrailing();
  }

  /**
   * Extracts direct child mapping keys as exporter names.
   *
   * @param block YAML-like block
   * @return direct child mapping keys
   */
  private static List<String> exporterNames(String block) {
    var names = new ArrayList<String>();
    for (var line : block.split("\\R")) {
      if (countLeadingSpaces(line) != 2) {
        continue;
      }
      var trimmed = line.trim();
      if (trimmed.endsWith(":")) {
        names.add(trimmed.substring(0, trimmed.length() - 1));
      }
    }
    return names;
  }

  /**
   * Extracts YAML list item values from a block.
   *
   * @param block YAML-like block
   * @return list item values
   */
  private static List<String> listItems(String block) {
    var items = new ArrayList<String>();
    for (var line : block.split("\\R")) {
      var trimmed = line.trim();
      if (trimmed.startsWith("- ")) {
        items.add(trimmed.substring(2).split("\\s+#", 2)[0].trim());
      }
    }
    return items;
  }

  /**
   * Checks whether a collector exporter name denotes OTLP over gRPC or HTTP/JSON.
   *
   * @param exporterName exporter name
   * @return true for OTLP exporter names
   */
  private static boolean isOtlpExporterName(String exporterName) {
    return "otlp".equals(exporterName)
        || exporterName.startsWith("otlp/")
        || exporterName.startsWith("otlp_grpc")
        || exporterName.startsWith("otlp_http")
        || exporterName.startsWith("otlphttp");
  }

  /**
   * Determines the OTLP transport protocol represented by an exporter.
   *
   * @param exportersBlock top-level exporters block
   * @param exporterName   exporter name
   * @return protocol name when the exporter represents an allowed protocol
   */
  private static Optional<String> otlpProtocolForExporter(String exportersBlock, String exporterName) {
    if (isOtlpGrpcExporterName(exporterName)) {
      return Optional.of("OTLP/gRPC");
    }
    if (isOtlpHttpExporterName(exporterName) && exporterUsesJsonEncoding(exportersBlock, exporterName)) {
      return Optional.of("OTLP/HTTP JSON");
    }
    return Optional.empty();
  }

  /**
   * Checks whether a collector exporter name denotes OTLP over gRPC.
   *
   * @param exporterName exporter name
   * @return true for OTLP/gRPC exporter names
   */
  private static boolean isOtlpGrpcExporterName(String exporterName) {
    return "otlp".equals(exporterName)
        || exporterName.startsWith("otlp/")
        || exporterName.startsWith("otlp_grpc");
  }

  /**
   * Checks whether a collector exporter name denotes OTLP over HTTP.
   *
   * @param exporterName exporter name
   * @return true for OTLP/HTTP exporter names
   */
  private static boolean isOtlpHttpExporterName(String exporterName) {
    return exporterName.startsWith("otlp_http")
        || exporterName.startsWith("otlphttp");
  }

  /**
   * Checks whether an OTLP/HTTP exporter explicitly uses JSON encoding.
   *
   * @param exportersBlock top-level exporters block
   * @param exporterName   exporter name
   * @return true if the exporter uses JSON encoding
   */
  private static boolean exporterUsesJsonEncoding(String exportersBlock, String exporterName) {
    var exporterBlock = firstBlock(exportersBlock, exporterName, 2);
    for (var line : exporterBlock.split("\\R")) {
      var trimmed = line.trim();
      if ("encoding: json".equals(trimmed)
          || "encoding: \"json\"".equals(trimmed)
          || "encoding: 'json'".equals(trimmed)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extracts the first YAML-like block with the requested key and indentation.
   *
   * @param content YAML-like content
   * @param key     mapping key
   * @param indent  expected leading spaces
   * @return matching block or empty string
   */
  private static String firstBlock(String content, String key, int indent) {
    if (content == null || content.isBlank()) {
      return "";
    }

    var lines = content.split("\\R", -1);
    var block = new StringBuilder();
    var inBlock = false;
    var header = key + ":";

    for (var line : lines) {
      var leadingSpaces = countLeadingSpaces(line);
      var trimmed = line.trim();
      if (!inBlock) {
        if (leadingSpaces == indent && trimmed.equals(header)) {
          inBlock = true;
          block.append(line).append(System.lineSeparator());
        }
        continue;
      }

      if (!trimmed.isBlank() && leadingSpaces <= indent && !(leadingSpaces == indent && trimmed.startsWith("- "))) {
        break;
      }
      block.append(line).append(System.lineSeparator());
    }
    return block.toString();
  }

  /**
   * Counts leading space characters in a line.
   *
   * @param line text line
   * @return number of leading spaces
   */
  private static int countLeadingSpaces(String line) {
    var count = 0;
    while (count < line.length() && line.charAt(count) == ' ') {
      count++;
    }
    return count;
  }

  /**
   * Verifies that exactly one pod contains the given container and that the requested Kubernetes probe is configured.
   *
   * @param namespace     namespace for the kubectl query
   * @param containerName target container name
   * @param probeName     probe to check (`livenessProbe`, `readinessProbe`, `startupProbe`)
   */
  @Und("prüfe im Namespace {tigerResolvedString} dass der Container {tigerResolvedString} eine {kubeProbe} konfiguriert hat")
  @And("verify in namespace {tigerResolvedString} that container {tigerResolvedString} has {kubeProbe} configured")
  public void verifyContainerHasProbeConfigured(String namespace, String containerName, String probeName) {
    var items = service.readPodsForNamespace(namespace);
    var matchingPodNames = new ArrayList<String>();
    JsonNode matchingContainer = null;
    String reportLine;

    for (var pod : items) {
      var containers = pod.path("spec").path("containers");
      if (!containers.isArray()) {
        continue;
      }
      var podName = pod.path("metadata").path("name").asText("<unknown>");
      for (var container : containers) {
        if (!containerName.equals(container.path("name").asText(""))) {
          continue;
        }
        matchingPodNames.add(podName);
        matchingContainer = container;
      }
    }

    if (matchingPodNames.isEmpty()) {
      var msg = "No container with name '" + containerName + "' found in namespace '" + namespace + "'.";
      reportLine = "CONTAINER=" + containerName + " | RESULT=NOT_FOUND";
      SoftAssertionsContext.recordSoftFailure(msg, new AssertionError(msg));
    } else if (matchingPodNames.size() > 1) {
      var msg = "Container '" + containerName + "' found in multiple pods in namespace '" + namespace
          + "': " + String.join(", ", matchingPodNames);
      reportLine = "CONTAINER=" + containerName + " | RESULT=AMBIGUOUS | PODS=" + String.join(",", matchingPodNames);
      SoftAssertionsContext.recordSoftFailure(msg, new AssertionError(msg));
    } else {
      var podName = matchingPodNames.getFirst();
      var probe = matchingContainer.path(probeName);
      if (probe.isMissingNode() || probe.isNull()) {
        var msg = "Container '" + containerName + "' in pod '" + podName + "' has no " + probeName + " configured.";
        reportLine = "POD=" + podName + " | CONTAINER=" + containerName + " | " + probeName + "=MISSING";
        SoftAssertionsContext.recordSoftFailure(msg, new AssertionError(msg));
      } else {
        reportLine =
            "POD=" + podName + " | CONTAINER=" + containerName + " | " + probeName + ":\n" + probe.toPrettyString();
      }
    }

    SerenityReportUtils.addCustomData(
        "Kubernetes probe check: " + containerName + " / " + probeName,
        reportLine);
  }

  /**
   * Verifies that the telemetry gateway exports traces asynchronously through a batch processor and an OTLP exporter.
   */
  @Und("prüfe, dass die Telemetrie-Gateway Collector-Konfiguration Traces per Batch exportiert")
  @And("verify that the telemetry gateway collector configuration exports traces by batch")
  public void verifyTelemetryGatewayExportsTracesByBatch() {
    var namespace = getNamespace();
    var configMapName = findTelemetryGatewayConfigMapName(namespace);
    var relayConfig = readOpenTelemetryCollectorRelayConfig(namespace, configMapName);
    var batchConfigured = tracesPipelineUsesBatch(relayConfig);
    var otlpExporter = firstTraceOtlpExporter(relayConfig).orElse("");

    var reportLine = "CONFIGMAP=" + configMapName
        + " | TRACES_BATCH=" + batchConfigured
        + " | TRACES_OTLP_EXPORTER=" + (otlpExporter.isBlank() ? "<missing>" : otlpExporter)
        + "\nTRACES_PIPELINE:\n" + tracePipelineForReport(relayConfig);

    if (!batchConfigured || otlpExporter.isBlank()) {
      var msg = "Telemetry gateway ConfigMap '" + configMapName
          + "' must export traces with the batch processor and an OTLP exporter.";
      SoftAssertionsContext.recordSoftFailure(msg, new AssertionError(msg));
    }

    SerenityReportUtils.addCustomData(
        "Telemetry gateway trace export configuration",
        reportLine);
  }

  /**
   * Verifies that the telemetry gateway forwards telemetry through at least one allowed OTLP protocol.
   */
  @Und("prüfe, dass die Telemetrie-Gateway Collector-Konfiguration Telemetriedaten per erlaubtem OTLP Protokoll weitergibt")
  @And("verify that the telemetry gateway collector configuration forwards telemetry by an allowed OTLP protocol")
  public void verifyTelemetryGatewayForwardsTelemetryByAllowedOtlpProtocol() {
    var namespace = getNamespace();
    var configMapName = findTelemetryGatewayConfigMapName(namespace);
    var relayConfig = readOpenTelemetryCollectorRelayConfig(namespace, configMapName);
    var activeProtocols = activeOtlpForwardingProtocols(relayConfig);
    var otlpExporters = configuredOtlpExporters(relayConfig);
    var forwardingPipelines = pipelinesUsingAnyExporter(relayConfig, otlpExporters);
    var activeProtocolsReport = activeProtocols.isEmpty() ? "<missing>" : String.join(",", activeProtocols);
    var otlpExportersReport = otlpExporters.isEmpty() ? "<missing>" : String.join(",", otlpExporters);
    var forwardingPipelinesReport = forwardingPipelines.isEmpty() ? "<missing>" : String.join(",", forwardingPipelines);

    var reportLine = "CONFIGMAP=" + configMapName
        + " | ACTIVE_OTLP_PROTOCOLS=" + activeProtocolsReport
        + " | OTLP_EXPORTERS=" + otlpExportersReport
        + " | PIPELINES_USING_OTLP=" + forwardingPipelinesReport
        + "\nSERVICE_PIPELINES:\n" + servicePipelinesForReport(relayConfig);

    if (activeProtocols.isEmpty()) {
      var msg = "Telemetry gateway ConfigMap '" + configMapName
          + "' must reference an OTLP/gRPC exporter or an OTLP/HTTP exporter with JSON encoding in a service"
          + " pipeline.";
      SoftAssertionsContext.recordSoftFailure(msg, new AssertionError(msg));
    }

    SerenityReportUtils.addCustomData(
        "Telemetry gateway active OTLP forwarding protocol",
        reportLine);
  }

  /**
   * Finds the telemetry gateway ConfigMap rendered by the zeta-guard Helm chart.
   *
   * @param namespace Kubernetes namespace
   * @return ConfigMap name
   */
  private String findTelemetryGatewayConfigMapName(String namespace) {
    service.verifyRequirements(namespace);
    var result = service.executeKubectlCommand(
        "-n", namespace, "get", "configmap", "-l", TELEMETRY_GATEWAY_CONFIGMAP_SELECTOR,
        "-o", "jsonpath={.items[*].metadata.name}");

    if (result.exitCode() != 0) {
      throw new AssertionError("Could not find telemetry gateway ConfigMap in namespace '" + namespace
          + "': " + result.stderr());
    }

    var configMapNamesOutput = result.stdout() == null ? "" : result.stdout();
    var names = Pattern.compile("\\s+").splitAsStream(configMapNamesOutput)
        .map(String::trim)
        .filter(name -> !name.isBlank())
        .toList();
    if (names.isEmpty()) {
      throw new AssertionError("No telemetry gateway ConfigMap found in namespace '" + namespace
          + "' with selector '" + TELEMETRY_GATEWAY_CONFIGMAP_SELECTOR + "'.");
    }
    if (names.size() > 1) {
      throw new AssertionError("Multiple telemetry gateway ConfigMaps found in namespace '" + namespace
          + "': " + String.join(", ", names));
    }
    return names.getFirst();
  }

  /**
   * Reads the OpenTelemetry Collector relay configuration from a ConfigMap.
   *
   * @param namespace     Kubernetes namespace
   * @param configMapName name of the OpenTelemetry Collector ConfigMap
   * @return relay configuration from `data.relay`
   */
  private String readOpenTelemetryCollectorRelayConfig(String namespace, String configMapName) {
    var result = service.executeKubectlCommand(
        "-n", namespace, "get", "configmap", configMapName, "-o", OPENTELEMETRY_RELAY_JSONPATH);

    if (result.exitCode() != 0) {
      throw new AssertionError("Could not read OpenTelemetry Collector ConfigMap '" + configMapName
          + "' in namespace '" + namespace + "': " + result.stderr());
    }

    var relayConfig = result.stdout();
    if (relayConfig == null || relayConfig.isBlank()) {
      throw new AssertionError("OpenTelemetry Collector ConfigMap '" + configMapName
          + "' in namespace '" + namespace + "' has no data.relay content.");
    }
    return relayConfig;
  }

  /**
   * Reads the configured ZETA namespace.
   *
   * @return configured Kubernetes namespace
   */
  private String getNamespace() {
    var namespace = TigerGlobalConfiguration.readStringOptional(ZETA_NAMESPACE_CONFIG_KEY)
        .map(TigerGlobalConfiguration::resolvePlaceholders)
        .orElse("");
    if (namespace.isBlank()) {
      throw new AssertionError("Missing configuration: " + ZETA_NAMESPACE_CONFIG_KEY);
    }
    return namespace;
  }
}
