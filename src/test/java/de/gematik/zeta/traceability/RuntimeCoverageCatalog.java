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

package de.gematik.zeta.traceability;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;

/**
 * Loads product and test-aspect catalogues needed by runtime coverage output.
 */
@Slf4j
final class RuntimeCoverageCatalog {

  private static final Path PRODUCT_STATUS_CSV =
      Path.of("docs/asciidoc/tables/source/product_implementation.csv");
  private static final Path TEST_ASPECTS_ROOT = Path.of("docs/asciidoc/testaspekte");

  private final Map<String, ProductInfo> productInfo = new LinkedHashMap<>();
  private final Map<String, TestAspectInfo> testAspectCatalog = new LinkedHashMap<>();

  /**
   * Create and load the runtime coverage catalogues.
   */
  RuntimeCoverageCatalog() {
    loadProductInfo();
    loadTestAspectCatalog();
  }

  /**
   * Return all known product requirement identifiers.
   *
   * @return product ids
   */
  Set<String> productIds() {
    return productInfo.keySet();
  }

  /**
   * Return product metadata for the given requirement.
   *
   * @param id requirement id
   * @return product metadata or null
   */
  ProductInfo productInfo(String id) {
    return productInfo.get(id);
  }

  /**
   * Return all known test aspect identifiers.
   *
   * @return test aspect ids
   */
  Set<String> testAspectIds() {
    return testAspectCatalog.keySet();
  }

  /**
   * Return test-aspect metadata for the given id.
   *
   * @param id test aspect id
   * @return test-aspect metadata or null
   */
  TestAspectInfo testAspectInfo(String id) {
    return testAspectCatalog.get(id);
  }

  /**
   * Compute the passed/total test aspect coverage for an AFO.
   *
   * @param requirementId     requirement id
   * @param mergedTestAspects merged test aspect state
   * @return two-element array with total and passed count
   */
  int[] computeTestAspectCoverage(String requirementId,
      Map<String, Rollup> mergedTestAspects) {
    if (testAspectCatalog.isEmpty()) {
      return new int[] {0, 0};
    }
    var total = 0;
    var passed = 0;
    for (var info : testAspectCatalog.values()) {
      if (!Objects.equals(requirementId, info.requirementId())) {
        continue;
      }
      total++;
      var rollup = mergedTestAspects.getOrDefault(info.id(), Rollup.empty());
      if (rollup.isPassed()) {
        passed++;
      }
    }
    if (total == 0) {
      return new int[] {0, 0};
    }
    return new int[] {total, passed};
  }

  /**
   * Count implemented test aspects for the given requirement.
   *
   * @param requirementId     requirement id
   * @param mergedTestAspects merged test aspect state
   * @return implemented test aspect count or null if the catalog is empty
   */
  Integer computeTestAspectImplementedCount(String requirementId,
      Map<String, Rollup> mergedTestAspects) {
    if (testAspectCatalog.isEmpty()) {
      return null;
    }
    var implemented = 0;
    for (var info : testAspectCatalog.values()) {
      if (!Objects.equals(requirementId, info.requirementId())) {
        continue;
      }
      var rollup = mergedTestAspects.getOrDefault(info.id(), Rollup.empty());
      if (rollup.total() > 0) {
        implemented++;
      }
    }
    return implemented;
  }

  /**
   * Load product implementation metadata from the CSV used by the test plan.
   */
  private void loadProductInfo() {
    if (!Files.exists(PRODUCT_STATUS_CSV)) {
      log.info("Product status CSV not found at {}, runtime coverage will omit product metadata.",
          PRODUCT_STATUS_CSV);
      return;
    }
    try (var reader = Files.newBufferedReader(PRODUCT_STATUS_CSV, StandardCharsets.UTF_8);
        var parser = CSVFormat.DEFAULT.builder()
            .setHeader()
            .setSkipHeaderRecord(true)
            .get()
            .parse(reader)) {
      var headerFields = new ArrayList<>(parser.getHeaderMap().keySet());
      if (headerFields.isEmpty()) {
        return;
      }
      headerFields.set(0, RuntimeCoverageIds.stripBom(headerFields.getFirst()));
      var requirementIndex = RuntimeCoverageCsvRepository.indexOf(headerFields, "Anforderung");
      var titleIndex = RuntimeCoverageCsvRepository.indexOf(headerFields, "Titel");
      var implementedIndex = RuntimeCoverageCsvRepository.indexOf(headerFields, "umgesetzt");
      var hintIndex = RuntimeCoverageCsvRepository.indexOf(headerFields, "Hinweis");

      for (var record : parser) {
        var requirement = RuntimeCoverageCsvRepository.getField(record, requirementIndex);
        if (requirement == null || requirement.isBlank()) {
          continue;
        }
        productInfo.put(requirement, new ProductInfo(
            requirement,
            RuntimeCoverageIds.defaultString(RuntimeCoverageCsvRepository.getField(record,
                titleIndex)),
            RuntimeCoverageIds.defaultString(RuntimeCoverageCsvRepository.getField(record,
                implementedIndex)),
            RuntimeCoverageIds.defaultString(RuntimeCoverageCsvRepository.getField(record,
                hintIndex))));
      }
    } catch (IOException exception) {
      throw new UncheckedIOException("Unable to read product implementation CSV", exception);
    }
  }

  /**
   * Load the test aspect catalog from generated Asciidoc files.
   */
  private void loadTestAspectCatalog() {
    if (!Files.exists(TEST_ASPECTS_ROOT)) {
      return;
    }
    try (var paths = Files.walk(TEST_ASPECTS_ROOT)) {
      paths.filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().startsWith("TA_"))
          .filter(path -> path.getFileName().toString().endsWith(".adoc"))
          .forEach(path -> {
            var id = RuntimeCoverageIds.stripAdocSuffix(path.getFileName().toString());
            var title = readTestAspectTitle(path, id);
            var requirementId = RuntimeCoverageIds.resolveRequirementFromTestAspect(id).orElse("");
            testAspectCatalog.put(id, new TestAspectInfo(id, title, requirementId));
          });
    } catch (IOException exception) {
      throw new UncheckedIOException("Unable to read test aspect catalog", exception);
    }
  }

  /**
   * Extract the test aspect title from its Asciidoc header.
   *
   * @param path test-aspect Asciidoc path
   * @param id   test-aspect id
   * @return title or empty string
   */
  private static String readTestAspectTitle(Path path, String id) {
    try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      String line;
      for (var i = 0; i < 5 && (line = reader.readLine()) != null; i++) {
        if (line.contains(id) && line.contains(" - ")) {
          return line.substring(line.indexOf(" - ") + 3).trim();
        }
      }
    } catch (IOException exception) {
      throw new UncheckedIOException("Unable to read test aspect title from " + path, exception);
    }
    return "";
  }
}
