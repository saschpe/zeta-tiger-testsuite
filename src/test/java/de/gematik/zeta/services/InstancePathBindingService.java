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

import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_POPP_TOKEN_GENERATOR_URL;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_SMCB_KEYSTORE_MANIFEST;
import static de.gematik.zeta.services.JMeterPropertySupport.buildLoadInstancePath;
import static de.gematik.zeta.services.JMeterPropertySupport.trimToNull;

import de.gematik.zeta.services.model.InstancePathBinding;
import de.gematik.zeta.services.model.SmcbPoppClaims;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

/**
 * Creates JMeter CSV bindings for load-driver instance paths and optional PoPP tokens.
 */
@Slf4j
public class InstancePathBindingService {

  private final LoadDriverClient loadDriverClient;
  private final SmcbKeystoreRepository smcbKeystoreRepository;
  private final PoppTokenService poppTokenService;

  /**
   * Creates a service with default dependencies.
   */
  public InstancePathBindingService() {
    this(new LoadDriverClient(), new SmcbKeystoreRepository(), new PoppTokenService());
  }

  /**
   * Creates a service with explicit dependencies.
   */
  public InstancePathBindingService(
      LoadDriverClient loadDriverClient,
      SmcbKeystoreRepository smcbKeystoreRepository,
      PoppTokenService poppTokenService) {
    this.loadDriverClient = loadDriverClient;
    this.smcbKeystoreRepository = smcbKeystoreRepository;
    this.poppTokenService = poppTokenService;
  }

  /**
   * Prepares an instance-path binding file, optionally including PoPP tokens.
   */
  public InstancePathBinding prepare(
      List<Integer> createdIds,
      String loadDriverBaseUrl,
      String proxyPath,
      String pathTemplate,
      boolean oneInstancePerClient,
      int loadThreads,
      Map<String, String> jmeterProps,
      int manifestOffset,
      boolean persistPoppBindings) throws Exception {
    var paths = buildInstancePaths(createdIds, proxyPath, pathTemplate);
    if (oneInstancePerClient && loadThreads > paths.size()) {
      throw new AssertionError(
          "LOAD_ONE_INSTANCE_PER_THREAD=true requires THREADS <= LOAD_INSTANCE_COUNT. threads="
              + loadThreads
              + ", instances=" + paths.size());
    }

    var poppTokenGeneratorUrl = trimToNull(jmeterProps.get(LOAD_POPP_TOKEN_GENERATOR_URL));
    var smcbManifestPath = trimToNull(jmeterProps.get(LOAD_SMCB_KEYSTORE_MANIFEST));

    if (poppTokenGeneratorUrl != null && smcbManifestPath != null) {
      var entries = smcbKeystoreRepository.loadManifestEntries(
          Path.of(smcbManifestPath).toAbsolutePath().normalize(), manifestOffset, paths.size());
      var poppClaims = poppTokenService.extractPoppClaims(entries);
      var poppTokens = poppTokenService.fetchPoppTokensBatch(
          loadDriverClient.createHttpClient(), poppTokenGeneratorUrl, poppClaims);
      if (persistPoppBindings) {
        persistPoppTokenBindings(loadDriverBaseUrl, paths, poppClaims, poppTokens);
      }
      return new InstancePathBinding(writeWithPoppTokens(paths, poppTokens), true);
    }
    return new InstancePathBinding(write(paths), false);
  }

  /**
   * Builds load-driver instance paths from ids.
   */
  public List<String> buildInstancePaths(
      List<Integer> createdIds, String proxyPath, String pathTemplate) {
    if (createdIds.isEmpty()) {
      throw new AssertionError("No load-driver instance IDs available to build request paths.");
    }
    return createdIds.stream()
        .map(id -> buildLoadInstancePath(id, proxyPath, pathTemplate))
        .collect(Collectors.toList());
  }

  /**
   * Writes a simple instance-path CSV file.
   */
  public Path write(List<String> paths) throws IOException {
    var file = Files.createTempFile("jmeter-instance-paths-", ".csv");
    Files.write(file, paths, StandardCharsets.UTF_8);
    return file;
  }

  /**
   * Writes an instance-path CSV file with aligned PoPP tokens.
   */
  public Path writeWithPoppTokens(List<String> paths, List<String> poppTokens)
      throws IOException {
    var file = Files.createTempFile("jmeter-instance-paths-", ".csv");
    List<String> lines = new ArrayList<>(paths.size() + 1);
    lines.add("instance_path,popp_token");
    for (var i = 0; i < paths.size(); i++) {
      var token = i < poppTokens.size() ? poppTokens.get(i) : "";
      lines.add(paths.get(i) + "," + token);
    }
    Files.write(file, lines, StandardCharsets.UTF_8);
    return file;
  }

  /**
   * Deletes a generated binding file or directory without failing the test.
   */
  public void deleteQuietly(Path path) {
    if (path == null) {
      return;
    }
    try {
      if (Files.isDirectory(path)) {
        try (var walk = Files.walk(path)) {
          walk.sorted(Comparator.reverseOrder()).forEach(current -> {
            try {
              Files.deleteIfExists(current);
            } catch (IOException e) {
              log.warn("Could not delete temporary instance paths entry '{}': {}",
                  current, e.getMessage());
            }
          });
        }
        return;
      }
      Files.deleteIfExists(path);
    } catch (IOException e) {
      log.warn("Could not delete temporary instance paths file '{}': {}", path, e.getMessage());
    }
  }

  /**
   * Persists generated PoPP bindings to a diagnostic CSV file.
   */
  public void persistPoppTokenBindings(
      String loadDriverBaseUrl,
      List<String> paths,
      List<SmcbPoppClaims> poppClaims,
      List<String> poppTokens) throws IOException {
    var directory = Path.of("target", "popp-bindings");
    Files.createDirectories(directory);

    var file = directory.resolve(
        "popp-binding-" + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")
            .format(LocalDateTime.now()) + ".csv");

    List<String> lines = new ArrayList<>(Math.min(paths.size(), poppTokens.size()) + 1);
    lines.add(
        "request_url,instance_path,expected_actor_id,expected_actor_profession_oid,token_actor_id,"
            + "token_actor_profession_oid,token_iss,popp_header");

    for (var i = 0; i < Math.min(paths.size(), poppTokens.size()); i++) {
      var token = poppTokens.get(i);
      lines.add(String.join(",",
          csvValue(loadDriverBaseUrl + paths.get(i)),
          csvValue(paths.get(i)),
          csvValue(poppClaims.get(i).actorId()),
          csvValue(poppClaims.get(i).actorProfessionOid()),
          csvValue(poppTokenService.extractJwtStringClaim(token, "actorId")),
          csvValue(poppTokenService.extractJwtStringClaim(token, "actorProfessionOid")),
          csvValue(poppTokenService.extractJwtStringClaim(token, "iss")),
          csvValue(token)));
    }

    Files.write(file, lines, StandardCharsets.UTF_8);
    log.info("Persisted PoPP bindings to {}", file.toAbsolutePath());
  }

  private String csvValue(String value) {
    if (value == null) {
      return "\"\"";
    }
    var sanitized = value.replace("\"", "\"\"");
    return "\"" + sanitized + "\"";
  }
}
