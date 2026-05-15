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

import de.gematik.zeta.services.model.SmcbManifestEntry;
import de.gematik.zeta.services.model.SmcbPoolEntry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Loads SMC-B keystore inputs from manifests and pool directories.
 */
public class SmcbKeystoreRepository {

  /**
   * Loads manifest entries in manifest order.
   */
  public List<SmcbManifestEntry> loadManifestEntries(
      Path manifestPath,
      int startIndex,
      int instanceCount) throws IOException {
    var lines = Files.readAllLines(manifestPath, StandardCharsets.UTF_8);
    if (lines.isEmpty()) {
      throw new AssertionError("SMC-B keystore manifest is empty: " + manifestPath);
    }

    var header = lines.getFirst().split("\t", -1);
    var stemIndex = findManifestColumn(header, "stem", manifestPath);
    var keystoreB64Index = findManifestColumn(header, "keystore_b64", manifestPath);
    var passwordIndex = findManifestColumn(header, "keystore_password", manifestPath);
    var aliasIndex = findManifestColumn(header, "keystore_alias", manifestPath);
    findManifestColumn(header, "store_type", manifestPath);

    var manifestDir = manifestPath.toAbsolutePath().normalize().getParent();
    var repoRoot = manifestDir == null ? null : manifestDir.getParent();
    if (repoRoot == null) {
      throw new AssertionError("Cannot resolve repository root for manifest: " + manifestPath);
    }

    var entries = new ArrayList<SmcbManifestEntry>(instanceCount);
    for (var i = startIndex + 1; i < lines.size() && entries.size() < instanceCount; i++) {
      var line = lines.get(i).trim();
      if (line.isEmpty()) {
        continue;
      }
      var values = line.split("\t", -1);
      var keystorePath = repoRoot.resolve(values[keystoreB64Index].trim())
          .toAbsolutePath()
          .normalize();
      if (!Files.exists(keystorePath)) {
        throw new AssertionError("SMC-B keystore payload does not exist: " + keystorePath);
      }
      entries.add(new SmcbManifestEntry(
          values[stemIndex].trim(),
          Files.readString(keystorePath, StandardCharsets.UTF_8).trim(),
          values[passwordIndex].trim(),
          values[aliasIndex].trim()));
    }
    return entries;
  }

  /**
   * Loads SMC-B keystore pool entries in deterministic filename order.
   */
  public List<SmcbPoolEntry> loadPoolEntries(
      Path poolDir, String keystorePassword, int requiredCount) throws IOException {
    if (!Files.isDirectory(poolDir)) {
      throw new AssertionError("SMC-B keystore pool directory does not exist: " + poolDir);
    }

    List<Path> keystoreFiles;
    try (var stream = Files.list(poolDir)) {
      keystoreFiles = stream
          .filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().endsWith(".p12"))
          .sorted(Comparator.comparing(path -> path.getFileName().toString()))
          .toList();
    }

    List<SmcbPoolEntry> entries = new ArrayList<>(Math.min(keystoreFiles.size(), requiredCount));
    for (var keystoreFile : keystoreFiles) {
      var fileName = keystoreFile.getFileName().toString();
      var stem = fileName.substring(0, fileName.length() - 4);
      var alias = stem.toLowerCase(Locale.ROOT);
      entries.add(new SmcbPoolEntry(
          stem,
          alias,
          Base64.getEncoder().encodeToString(Files.readAllBytes(keystoreFile))));
      if (entries.size() >= requiredCount) {
        break;
      }
    }
    return entries;
  }

  /**
   * Validates common SMC-B manifest create inputs.
   */
  public void validateManifestCreateInputs(String manifestPath, String fachdienstUrl) {
    if (fachdienstUrl == null) {
      throw new AssertionError(
          "LOAD_CREATE_BODY_INLINE=true with -J"
              + JMeterPropertySupport.LOAD_SMCB_KEYSTORE_MANIFEST
              + " requires -JLOAD_FACHDIENST_URL.");
    }
    var resolvedManifestPath = Path.of(manifestPath).toAbsolutePath().normalize();
    if (!Files.exists(resolvedManifestPath)) {
      throw new AssertionError("SMC-B keystore manifest does not exist: " + resolvedManifestPath);
    }
  }

  private int findManifestColumn(String[] header, String requiredColumn, Path manifestPath) {
    for (var i = 0; i < header.length; i++) {
      if (requiredColumn.equalsIgnoreCase(header[i].trim())) {
        return i;
      }
    }
    throw new AssertionError(
        "SMC-B keystore manifest " + manifestPath + " is missing required column: "
            + requiredColumn);
  }
}
