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

import io.cucumber.plugin.event.Status;

/**
 * Aggregates scenario counts for one requirement or test aspect.
 */
final class Rollup {

  private static final Rollup EMPTY = new Rollup();
  private int total;
  private int passed;
  private int failed;
  private int skipped;

  /**
   * Return the shared empty rollup instance.
   *
   * @return shared empty rollup instance
   */
  static Rollup empty() {
    return EMPTY;
  }

  /**
   * Create a rollup from persisted counters.
   *
   * @param total   total scenarios
   * @param passed  passed scenarios
   * @param failed  failed scenarios
   * @param skipped skipped scenarios
   * @return populated rollup
   */
  static Rollup fromCounts(int total, int passed, int failed, int skipped) {
    var rollup = new Rollup();
    rollup.total = Math.max(0, total);
    rollup.passed = Math.max(0, passed);
    rollup.failed = Math.max(0, failed);
    rollup.skipped = Math.max(0, skipped);
    return rollup;
  }

  /**
   * Record one scenario outcome.
   *
   * @param status scenario status
   */
  synchronized void record(Status status) {
    total++;
    if (status == Status.PASSED) {
      passed++;
    } else if (status == Status.SKIPPED) {
      skipped++;
    } else {
      failed++;
    }
  }

  /**
   * Resolve the aggregate status for reporting.
   *
   * @return rendered status
   */
  synchronized String status() {
    if (failed > 0) {
      if (passed > 0) {
        return "teilweise fehlgeschlagen";
      }
      return "fehlgeschlagen";
    }
    if (passed > 0) {
      return "bestanden";
    }
    if (skipped > 0) {
      return "übersprungen";
    }
    return "nicht ausgeführt";
  }

  /**
   * Returns true if all recorded scenarios passed and at least one ran.
   *
   * @return true for a successful non-empty rollup
   */
  synchronized boolean isPassed() {
    return total > 0 && failed == 0 && passed > 0;
  }

  /**
   * Return the total number of recorded scenarios.
   *
   * @return total number of recorded scenarios
   */
  synchronized int total() {
    return total;
  }

  /**
   * Return the number of passed scenarios.
   *
   * @return number of passed scenarios
   */
  synchronized int passed() {
    return passed;
  }

  /**
   * Return the number of failed scenarios.
   *
   * @return number of failed scenarios
   */
  synchronized int failed() {
    return failed;
  }

  /**
   * Return the number of skipped scenarios.
   *
   * @return number of skipped scenarios
   */
  synchronized int skipped() {
    return skipped;
  }

  /**
   * Add another rollup into this instance.
   *
   * @param other rollup to merge
   */
  synchronized void add(Rollup other) {
    if (other == null) {
      return;
    }
    total += other.total;
    passed += other.passed;
    failed += other.failed;
    skipped += other.skipped;
  }

  /**
   * Create a snapshot copy of this rollup.
   *
   * @return copied rollup
   */
  synchronized Rollup copy() {
    return fromCounts(total, passed, failed, skipped);
  }
}
