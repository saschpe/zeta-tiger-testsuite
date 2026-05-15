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

import java.util.Set;

/**
 * Runtime failure context persisted until the final aggregate writer runs.
 *
 * @param error         compact runtime error message
 * @param testAspectIds test aspect identifiers attached to the failed scenario
 * @param feature       feature URI or path
 * @param scenario      scenario name
 */
record FailureRecord(String error, Set<String> testAspectIds, String feature, String scenario) {

  /**
   * Normalize context fields for stable matching.
   */
  FailureRecord {
    error = RuntimeCoverageIds.defaultString(error).trim();
    testAspectIds = RuntimeCoverageIds.normalizeIds(testAspectIds);
    feature = RuntimeCoverageIds.normalizePath(feature);
    scenario = RuntimeCoverageIds.defaultString(scenario).trim();
  }
}
