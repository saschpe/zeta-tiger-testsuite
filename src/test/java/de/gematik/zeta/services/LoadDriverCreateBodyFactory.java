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

import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_CREATE_BODY_INLINE;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_SMCB_KEYSTORE_MANIFEST;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_SMCB_KEYSTORE_PASSWORD;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_SMCB_KEYSTORE_POOL_DIR;
import static de.gematik.zeta.services.JMeterPropertySupport.parseBoolean;
import static de.gematik.zeta.services.JMeterPropertySupport.trimToNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.gematik.zeta.services.model.LoadDriverCreateRequest;
import de.gematik.zeta.services.model.LoadDriverInstanceConfig;
import de.gematik.zeta.services.model.SmcbManifestEntry;
import de.gematik.zeta.services.model.SmcbPoolEntry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds load-driver create_instances request bodies.
 */
public class LoadDriverCreateBodyFactory {

  private static final ObjectMapper JSON = new ObjectMapper();

  private final SmcbKeystoreRepository smcbKeystoreRepository;

  /**
   * Creates a factory using the default SMC-B keystore repository.
   */
  public LoadDriverCreateBodyFactory() {
    this(new SmcbKeystoreRepository());
  }

  /**
   * Creates a factory with explicit dependencies.
   */
  public LoadDriverCreateBodyFactory(SmcbKeystoreRepository smcbKeystoreRepository) {
    this.smcbKeystoreRepository = smcbKeystoreRepository;
  }

  /**
   * Generates an inline create body when requested by properties.
   */
  public String generateIfNeeded(
      Map<String, String> jmeterProps, int instanceCount, boolean autoInit)
      throws IOException {
    rejectDeprecatedCreateBodyInputs(jmeterProps);

    var inlineEnabled = parseBoolean(jmeterProps.get(LOAD_CREATE_BODY_INLINE), false);
    if (!inlineEnabled) {
      return "";
    }

    var fachdienstUrl = trimToNull(jmeterProps.get("LOAD_FACHDIENST_URL"));
    var smcbManifestPath = trimToNull(jmeterProps.get(LOAD_SMCB_KEYSTORE_MANIFEST));
    if (smcbManifestPath != null) {
      smcbKeystoreRepository.validateManifestCreateInputs(smcbManifestPath, fachdienstUrl);
      return "";
    }
    var smcbPoolDir = trimToNull(jmeterProps.get(LOAD_SMCB_KEYSTORE_POOL_DIR));
    if (smcbPoolDir != null) {
      return fromSmcbKeystorePool(
          smcbPoolDir,
          fachdienstUrl,
          resolveSmcbKeystorePoolPassword(jmeterProps),
          instanceCount,
          autoInit);
    }

    var keystoreAlias = trimToNull(jmeterProps.get("LOAD_COMMON_KEY_ALIAS"));
    var keystorePassword = trimToNull(jmeterProps.get("LOAD_COMMON_KEY_PASSWORD"));
    var keystoreB64 = resolveLoadCommonKeystoreB64(jmeterProps);

    if (fachdienstUrl == null || keystoreAlias == null || keystorePassword == null
        || keystoreB64 == null) {
      throw new AssertionError(
          "LOAD_CREATE_BODY_INLINE=true requires all of "
              + "-JLOAD_FACHDIENST_URL, -JLOAD_COMMON_KEYSTORE_B64 (or "
              + "-JLOAD_COMMON_KEYSTORE_B64_FILE), -JLOAD_COMMON_KEY_ALIAS, "
              + "-JLOAD_COMMON_KEY_PASSWORD.");
    }

    var instances = new ArrayList<LoadDriverInstanceConfig>(instanceCount);
    for (var i = 0; i < instanceCount; i++) {
      instances.add(new LoadDriverInstanceConfig(
          fachdienstUrl, true, keystoreB64, keystoreAlias, keystorePassword));
    }
    return JSON.writeValueAsString(new LoadDriverCreateRequest(instanceCount, autoInit, instances));
  }

  /**
   * Creates a batched body from an existing create body.
   */
  public String buildBatch(
      JsonNode createBodyRoot,
      String originalBody,
      int batchStart,
      int batchCount,
      boolean autoInit) throws IOException {
    if (createBodyRoot == null) {
      return "";
    }

    var instancesNode = createBodyRoot.path("instances");
    if (!instancesNode.isArray()) {
      if (batchStart == 0) {
        return originalBody;
      }
      throw new AssertionError(
          "Batched load-driver create requires instances-array in create body.");
    }

    var batchRoot = JSON.createObjectNode();
    batchRoot.put("count", batchCount);
    batchRoot.put("autoInit", autoInit);
    var batchInstances = batchRoot.putArray("instances");

    for (var i = batchStart; i < batchStart + batchCount; i++) {
      var instanceNode = instancesNode.get(i);
      if (instanceNode == null) {
        throw new AssertionError(
            "Create body has fewer instance configs than expected. batchStart=" + batchStart
                + ", batchCount=" + batchCount + ", index=" + i);
      }
      batchInstances.add(instanceNode);
    }

    return JSON.writeValueAsString(batchRoot);
  }

  /**
   * Builds one create_instances request body from one manifest-backed batch.
   */
  public String fromSmcbEntries(
      List<SmcbManifestEntry> entries, String fachdienstUrl, boolean autoInit) throws IOException {
    var instances = entries.stream()
        .map(entry -> new LoadDriverInstanceConfig(
            fachdienstUrl, true, entry.keystoreB64(), entry.keystoreAlias(), entry.keystorePassword()))
        .toList();
    return JSON.writeValueAsString(new LoadDriverCreateRequest(entries.size(), autoInit, instances));
  }

  private String fromSmcbKeystorePool(
      String smcbKeystorePoolDir,
      String fachdienstUrl,
      String keystorePassword,
      int instanceCount,
      boolean autoInit) throws IOException {
    if (fachdienstUrl == null || keystorePassword == null) {
      throw new AssertionError(
          "LOAD_CREATE_BODY_INLINE=true with -J" + LOAD_SMCB_KEYSTORE_POOL_DIR
              + " requires -JLOAD_FACHDIENST_URL and -J" + LOAD_SMCB_KEYSTORE_PASSWORD + ".");
    }

    var poolEntries = smcbKeystoreRepository.loadPoolEntries(
        Path.of(smcbKeystorePoolDir), keystorePassword, instanceCount);
    if (poolEntries.size() < instanceCount) {
      throw new AssertionError("SMC-B keystore pool " + smcbKeystorePoolDir + " contains only "
          + poolEntries.size() + " usable entries, but " + instanceCount + " instances were requested.");
    }

    var instances = new ArrayList<LoadDriverInstanceConfig>(instanceCount);
    for (var i = 0; i < instanceCount; i++) {
      var entry = poolEntries.get(i);
      instances.add(new LoadDriverInstanceConfig(
          fachdienstUrl, true, entry.keystoreB64(), entry.alias(), keystorePassword));
    }
    return JSON.writeValueAsString(new LoadDriverCreateRequest(instanceCount, autoInit, instances));
  }

  /**
   * Resolves the effective instance count from properties or create body.
   */
  public int resolveExpectedInstanceCount(
      Map<String, String> jmeterProps, String createBody, int configuredCount) {
    if (jmeterProps.containsKey("LOAD_INSTANCE_COUNT")) {
      return configuredCount;
    }
    try {
      var node = JSON.readTree(createBody);
      var bodyCount = node.path("count").asInt(configuredCount);
      return bodyCount > 0 ? bodyCount : configuredCount;
    } catch (Exception ignored) {
      return configuredCount;
    }
  }

  private void rejectDeprecatedCreateBodyInputs(Map<String, String> jmeterProps) {
    if (trimToNull(jmeterProps.get("LOAD_CREATE_BODY")) != null) {
      throw new AssertionError(
          "LOAD_CREATE_BODY is not supported anymore. Use -JLOAD_CREATE_BODY_INLINE=true.");
    }
    if (trimToNull(jmeterProps.get("LOAD_CREATE_BODY_FILE")) != null) {
      throw new AssertionError(
          "LOAD_CREATE_BODY_FILE is not supported anymore. Use -JLOAD_CREATE_BODY_INLINE=true.");
    }
  }

  private String resolveSmcbKeystorePoolPassword(Map<String, String> jmeterProps) {
    var password = trimToNull(jmeterProps.get(LOAD_SMCB_KEYSTORE_PASSWORD));
    if (password != null) {
      return password;
    }
    return trimToNull(jmeterProps.get("LOAD_COMMON_KEY_PASSWORD"));
  }

  private String resolveLoadCommonKeystoreB64(Map<String, String> jmeterProps) throws IOException {
    var inlineB64 = trimToNull(jmeterProps.get("LOAD_COMMON_KEYSTORE_B64"));
    if (inlineB64 != null) {
      return inlineB64;
    }

    var b64File = trimToNull(jmeterProps.get("LOAD_COMMON_KEYSTORE_B64_FILE"));
    if (b64File == null) {
      return null;
    }

    var path = Path.of(b64File);
    if (!Files.exists(path)) {
      throw new AssertionError("LOAD_COMMON_KEYSTORE_B64_FILE does not exist: " + path);
    }

    var content = Files.readString(path, StandardCharsets.UTF_8).trim();
    if (content.isEmpty()) {
      throw new AssertionError("LOAD_COMMON_KEYSTORE_B64_FILE is empty: " + path);
    }
    return content;
  }
}
