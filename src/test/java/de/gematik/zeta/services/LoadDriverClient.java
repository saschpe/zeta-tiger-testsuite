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

package de.gematik.zeta.services;

import static de.gematik.zeta.services.JMeterPropertySupport.buildLoadInstancePath;
import static de.gematik.zeta.services.JMeterPropertySupport.sanitizeLogBody;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.zeta.services.model.CreateBatchDescriptor;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import lombok.extern.slf4j.Slf4j;

/**
 * HTTP client facade for load-driver control operations.
 */
@Slf4j
public class LoadDriverClient {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final int CREATE_PARALLEL_BATCHES = 4;
  private static final String DISABLE_TLS_VERIFICATION_PROPERTY =
      "zeta.loadDriver.disableTlsVerification";
  private static final String DISABLE_TLS_VERIFICATION_ENV =
      "ZETA_LOAD_DRIVER_DISABLE_TLS_VERIFICATION";

  /**
   * Creates a load-driver HTTP client that accepts test certificates.
   *
   * @return configured HTTP client
   */
  public HttpClient createHttpClient() throws Exception {
    if (!isTlsVerificationDisabled()) {
      return HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(10))
          .build();
    }

    log.warn(
        "Load-driver TLS certificate validation is disabled. Set {}=false or {}=false to use default JVM validation.",
        DISABLE_TLS_VERIFICATION_PROPERTY,
        DISABLE_TLS_VERIFICATION_ENV);
    TrustManager[] trustAll = new TrustManager[]{
        new X509TrustManager() {
          @Override
          public void checkClientTrusted(X509Certificate[] chain, String authType) {
          }

          @Override
          public void checkServerTrusted(X509Certificate[] chain, String authType) {
          }

          @Override
          public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
          }
        }
    };

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustAll, new SecureRandom());
    SSLParameters sslParameters = new SSLParameters();
    sslParameters.setEndpointIdentificationAlgorithm(null);

    return HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .sslContext(sslContext)
        .sslParameters(sslParameters)
        .build();
  }

  /**
   * Resolves whether load-driver TLS certificate validation should be disabled.
   *
   * @return {@code true} when the trust-all test client should be used
   */
  private boolean isTlsVerificationDisabled() {
    var propertyValue = System.getProperty(DISABLE_TLS_VERIFICATION_PROPERTY);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return Boolean.parseBoolean(propertyValue.trim());
    }

    var envValue = System.getenv(DISABLE_TLS_VERIFICATION_ENV);
    if (envValue != null && !envValue.isBlank()) {
      return Boolean.parseBoolean(envValue.trim());
    }

    return true;
  }

  /**
   * Executes prepared load-driver create_instances request batches in parallel.
   */
  public List<Integer> executeCreateBatches(
      HttpClient client, int instanceCount, List<CreateBatchDescriptor> batches) throws Exception {
    int totalBatches = batches.size();
    log.info("Creating {} load-driver instances in {} batches with parallelism {}",
        instanceCount, totalBatches, CREATE_PARALLEL_BATCHES);
    var executor = Executors.newFixedThreadPool(CREATE_PARALLEL_BATCHES);
    @SuppressWarnings("unchecked")
    Future<List<Integer>>[] futures = new Future[totalBatches];
    long t0 = System.nanoTime();
    for (int i = 0; i < totalBatches; i++) {
      final int batchNum = i + 1;
      final CreateBatchDescriptor batch = batches.get(i);
      futures[i] = executor.submit(() -> createOneBatch(client, batch, batchNum, totalBatches, t0));
    }
    try {
      var ids = new ArrayList<Integer>(instanceCount);
      for (int i = 0; i < totalBatches; i++) {
        ids.addAll(futures[i].get());
      }
      log.info("Created {} load-driver instances from {} batches in {}ms",
          ids.size(), totalBatches, Duration.ofNanos(System.nanoTime() - t0).toMillis());
      return ids;
    } catch (java.util.concurrent.ExecutionException e) {
      throw new IOException("create_instances batch failed", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while waiting for create_instances batch", e);
    } finally {
      executor.shutdownNow();
    }
  }

  private List<Integer> createOneBatch(
      HttpClient client,
      CreateBatchDescriptor batch,
      int batchNum,
      int totalBatches,
      long startedNanos) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(batch.uri())
        .header("Content-Type", "application/json")
        .timeout(Duration.ofMinutes(5))
        .POST(HttpRequest.BodyPublishers.ofString(batch.batchBody(), StandardCharsets.UTF_8))
        .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() < 200 || response.statusCode() > 299) {
      throw new AssertionError("Load-driver create_instances failed: HTTP "
          + response.statusCode() + " body=" + sanitizeLogBody(response.body()));
    }
    JsonNode root = JSON.readTree(response.body());
    JsonNode idsNode = root.path("ids");
    if (!idsNode.isArray()) {
      throw new AssertionError("Load-driver create_instances response has no ids-array: "
          + sanitizeLogBody(response.body()));
    }
    var batchIds = new ArrayList<Integer>(batch.batchCount());
    for (JsonNode idNode : idsNode) {
      if (idNode.canConvertToInt()) {
        batchIds.add(idNode.asInt());
      }
    }
    int created = root.path("created").asInt(batchIds.size());
    if (batchIds.size() != batch.batchCount() || created != batchIds.size()) {
      throw new AssertionError("Load-driver created ids mismatch: expected=" + batch.batchCount()
          + ", created=" + created + ", ids=" + batchIds.size());
    }
    log.info("create_instances batch {}/{} done in {}ms total elapsed",
        batchNum, totalBatches, Duration.ofNanos(System.nanoTime() - startedNanos).toMillis());
    return batchIds;
  }

  /**
   * Waits until all expected instances reach one of the target states.
   */
  public void waitForInstancesState(
      HttpClient client,
      String loadDriverBaseUrl,
      List<Integer> expectedIds,
      Set<String> targetStates,
      Duration timeout,
      Duration pollInterval) throws Exception {
    Set<String> normalizedTargets = targetStates.stream()
        .map(state -> state.toUpperCase(Locale.ROOT))
        .collect(Collectors.toSet());
    long deadlineNanos = System.nanoTime() + timeout.toNanos();
    Set<Integer> expectedSet = new HashSet<>(expectedIds);
    while (System.nanoTime() < deadlineNanos) {
      Map<Integer, String> states = getInstanceStates(client, loadDriverBaseUrl);
      Set<Integer> matching = expectedSet.stream()
          .filter(id -> normalizedTargets.contains(states.getOrDefault(id, "").toUpperCase(Locale.ROOT)))
          .collect(Collectors.toSet());
      Set<Integer> failed = expectedSet.stream()
          .filter(id -> "FAILED".equalsIgnoreCase(states.get(id)))
          .collect(Collectors.toSet());

      if (!failed.isEmpty()) {
        throw new AssertionError(
            "Load-driver instances failed while waiting for states " + normalizedTargets
                + ". failedIds=" + failed + ", states=" + states);
      }
      if (matching.size() == expectedSet.size()) {
        return;
      }
      Thread.sleep(Math.max(100, pollInterval.toMillis()));
    }
    Map<Integer, String> finalStates = getInstanceStates(client, loadDriverBaseUrl);
    throw new AssertionError(
        "Timeout while waiting for instances in states " + normalizedTargets + ". expected="
            + expectedSet + ", states=" + finalStates);
  }

  /**
   * Returns current load-driver instance states keyed by id.
   */
  public Map<Integer, String> getInstanceStates(
      HttpClient client, String loadDriverBaseUrl) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(loadDriverBaseUrl + "/load/list_instances"))
        .timeout(Duration.ofSeconds(30))
        .GET()
        .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() < 200 || response.statusCode() > 299) {
      throw new AssertionError("Load-driver list_instances failed: HTTP " + response.statusCode());
    }

    JsonNode root = JSON.readTree(response.body());
    Map<Integer, String> states = new HashMap<>();
    if (root.isArray()) {
      for (JsonNode node : root) {
        readInstanceState(node, null, states);
      }
      return states;
    }

    JsonNode instancesNode = root.path("instances");
    if (instancesNode.isArray()) {
      for (JsonNode node : instancesNode) {
        readInstanceState(node, null, states);
      }
      return states;
    }

    if (root.isObject()) {
      root.properties().forEach(entry -> readInstanceState(entry.getValue(), entry.getKey(), states));
    }
    return states;
  }

  private void readInstanceState(JsonNode node, String fallbackId, Map<Integer, String> states) {
    if (node == null || node.isNull()) {
      return;
    }
    int id = node.path("id").asInt(Integer.MIN_VALUE);
    if (id == Integer.MIN_VALUE) {
      id = node.path("instanceIndex").asInt(Integer.MIN_VALUE);
    }
    if (id == Integer.MIN_VALUE && fallbackId != null) {
      try {
        id = Integer.parseInt(fallbackId);
      } catch (NumberFormatException ignored) {
        return;
      }
    }
    if (id == Integer.MIN_VALUE) {
      return;
    }

    String state = node.path("state").asText("");
    if (state.isBlank() && node.isTextual()) {
      state = node.asText("");
    }
    states.put(id, state);
  }

  /**
   * Deletes all load-driver instances and logs cleanup failures without failing the test.
   */
  public void deleteAllInstances(HttpClient client, String loadDriverBaseUrl) {
    try {
      HttpRequest request = HttpRequest.newBuilder(URI.create(loadDriverBaseUrl + "/load/delete_instances"))
          .timeout(Duration.ofSeconds(30))
          .DELETE()
          .build();
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      log.info("Load-driver cleanup status={}", response.statusCode());
    } catch (Exception e) {
      log.warn("Load-driver cleanup failed: {}", e.getMessage());
    }
  }

  /**
   * Resets the given instances via the configured path template.
   */
  public void resetInstances(
      HttpClient client,
      String loadDriverBaseUrl,
      List<Integer> instanceIds,
      String pathTemplate,
      Duration stepTimeout) throws Exception {
    for (int instanceId : instanceIds) {
      String path = buildLoadInstancePath(instanceId, "/reset", pathTemplate);
      HttpRequest request = HttpRequest.newBuilder(URI.create(loadDriverBaseUrl + path))
          .timeout(stepTimeout)
          .GET()
          .build();
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() < 200 || response.statusCode() > 299) {
        throw new AssertionError(
            "Load-driver reset failed for instanceId=" + instanceId
                + ", path=" + path
                + ", status=" + response.statusCode()
                + ", body=" + sanitizeLogBody(response.body()));
      }
    }
  }

  /**
   * Executes an initialization flow for the given instances.
   */
  public void runInitFlow(
      HttpClient client,
      String loadDriverBaseUrl,
      List<Integer> createdIds,
      String pathTemplate,
      List<String> initFlow,
      Duration stepTimeout) throws Exception {
    log.info("Executing load-driver init flow {} for {} instances", initFlow, createdIds.size());
    for (int instanceId : createdIds) {
      for (String initPath : initFlow) {
        String path = buildLoadInstancePath(instanceId, initPath, pathTemplate);
        URI uri = URI.create(loadDriverBaseUrl + path);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri).timeout(stepTimeout);

        HttpResponse<String> response = client.send(
            requestBuilder.GET().build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() > 299) {
          throw new AssertionError(
              "Load-driver init flow failed for instanceId=" + instanceId
                  + ", path=" + path
                  + ", status=" + response.statusCode()
                  + ", body=" + sanitizeLogBody(response.body()));
        }
      }
    }
  }

  /**
   * Runs a small request precheck against created instances.
   */
  public void runPrecheck(
      HttpClient client,
      String loadDriverBaseUrl,
      List<Integer> createdIds,
      String proxyPath,
      String pathTemplate,
      String method,
      int sampleSize) throws Exception {
    Map<Integer, String> initialStates = safeStates(client, loadDriverBaseUrl);
    if (!initialStates.isEmpty()) {
      log.info(
          "Load-driver precheck list_instances: {}",
          summarizeStates(createdIds, initialStates));
    }

    int checks = Math.min(sampleSize, createdIds.size());
    for (int i = 0; i < checks; i++) {
      int instanceId = createdIds.get(i);
      String path = buildLoadInstancePath(instanceId, proxyPath, pathTemplate);
      URI uri = URI.create(loadDriverBaseUrl + path);

      HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
          .timeout(Duration.ofSeconds(30));
      HttpRequest request = buildPrecheckRequest(requestBuilder, method);

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() < 200 || response.statusCode() > 299) {
        String hint = buildPrecheckHint(response.statusCode(), loadDriverBaseUrl, path);
        Map<Integer, String> currentStates = safeStates(client, loadDriverBaseUrl);
        String stateInfo = currentStates.isEmpty()
            ? "unavailable"
            : summarizeStates(createdIds, currentStates);
        throw new AssertionError(
            "Load-driver precheck failed for instanceId=" + instanceId
                + ", method=" + method
                + ", path=" + path
                + ", status=" + response.statusCode()
                + ", body=" + sanitizeLogBody(response.body())
                + ", list_instances=" + stateInfo
                + hint);
      }
    }
  }

  /**
   * Reads states for diagnostics, returning an empty map when the request fails.
   */
  public Map<Integer, String> safeStates(HttpClient client, String loadDriverBaseUrl) {
    try {
      return getInstanceStates(client, loadDriverBaseUrl);
    } catch (Exception e) {
      log.warn("Load-driver list_instances during precheck failed: {}", e.getMessage());
      return Map.of();
    }
  }

  private String summarizeStates(List<Integer> createdIds, Map<Integer, String> states) {
    return createdIds.stream()
        .map(id -> id + ":" + states.getOrDefault(id, "MISSING"))
        .collect(Collectors.joining(", ", "[", "]"));
  }

  private String buildPrecheckHint(int statusCode, String loadDriverBaseUrl, String path) {
    if (statusCode != 403 || !path.startsWith("/loaddriver-api/")) {
      return "";
    }
    boolean likelyExternalIngress =
        loadDriverBaseUrl.startsWith("https://")
            || loadDriverBaseUrl.contains("zeta-kind.local");
    if (likelyExternalIngress) {
      return " (hint: '/loaddriver-api/*' returned 403 via ingress; "
          + "verify load-driver route/security config and instance state)";
    }
    return " (hint: '/loaddriver-api/*' returned 403; "
        + "verify load-driver route/security config and instance state)";
  }

  private HttpRequest buildPrecheckRequest(HttpRequest.Builder requestBuilder, String method) {
    if (!"GET".equals(method)) {
      throw new AssertionError(
          "Unsupported LOAD_PRECHECK_METHOD/HTTP_METHOD for precheck: " + method
              + ". Supported: GET");
    }
    return requestBuilder.GET().build();
  }
}
