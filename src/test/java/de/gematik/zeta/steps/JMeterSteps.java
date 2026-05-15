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

import static de.gematik.zeta.services.JMeterPropertySupport.requireProperty;
import static de.gematik.zeta.services.JMeterPropertySupport.resolveTigerPlaceholders;

import de.gematik.zeta.perf.PlanRunnerService;
import de.gematik.zeta.services.LoadDriverPreparationService;
import de.gematik.zeta.services.model.LoadDriverContext;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.de.Wenn;
import io.cucumber.java.en.When;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;

/**
 * Cucumber step definitions for running JMeter DSL plans and load-driver preparation.
 */
@Slf4j
public class JMeterSteps {

  private final PlanRunnerService planRunnerService;
  private final LoadDriverPreparationService loadDriverPreparationService;

  /**
   * Creates JMeter steps with default services.
   */
  public JMeterSteps() {
    this(new PlanRunnerService(), new LoadDriverPreparationService());
  }

  /**
   * Creates JMeter steps with explicit services.
   *
   * @param planRunnerService            service for running DSL plans
   * @param loadDriverPreparationService service for load-driver setup
   */
  JMeterSteps(
      PlanRunnerService planRunnerService,
      LoadDriverPreparationService loadDriverPreparationService) {
    this.planRunnerService = planRunnerService;
    this.loadDriverPreparationService = loadDriverPreparationService;
  }

  /**
   * Runs a JMeter plan with optional CLI-like arguments from a DataTable.
   *
   * @param planPath  path to JMeter plan identifier
   * @param argsTable optional flags/values (supported: -f, -l, -Jkey=val)
   */
  @Wenn("ich JMeter mit dem Plan {tigerResolvedString} starte")
  @Wenn("JMeter mit dem Plan {tigerResolvedString} gestartet wird")
  @When("I start JMeter with plan {tigerResolvedString}")
  @When("JMeter is startet with the plan {tigerResolvedString}")
  public void runJMeterWithPlan(String planPath, DataTable argsTable) throws Exception {
    log.info("Starting JMeter with plan: {}", planPath);

    Map<String, String> jmeterProps = parseJMeterProperties(argsTable);
    jmeterProps.put("__PLAN_PATH__", planPath);

    LoadDriverContext loadDriverContext = jmeterProps.containsKey("LOAD_DRIVER_BASE_URL")
        ? loadDriverPreparationService.prepare(jmeterProps)
        : null;

    AtomicBoolean backgroundResetStop = new AtomicBoolean(false);
    Thread backgroundResetThread =
        loadDriverPreparationService.startBackgroundResetThread(loadDriverContext, backgroundResetStop);

    try {
      int targetRps = Integer.parseInt(jmeterProps.getOrDefault("TARGET_RPS", "300"));
      String baseUrl = requireProperty(jmeterProps, "BASE_URL");

      log.info("JMeter config: targetRps={}, baseUrl={}", targetRps, baseUrl);
      if (jmeterProps.containsKey("__WAVES_DONE__")) {
        log.info("Skipping JMeter run: waves already executed JMeter internally");
      } else {
        planRunnerService.runDslPlan(planPath, baseUrl, targetRps, jmeterProps);
      }
    } finally {
      stopBackgroundReset(backgroundResetThread, backgroundResetStop);
      cleanupLoadDriver(loadDriverContext);
    }
  }

  /**
   * Parses the optional Cucumber argument table into JMeter property flags.
   *
   * @param argsTable optional Cucumber table
   * @return parsed JMeter properties
   */
  private Map<String, String> parseJMeterProperties(DataTable argsTable) {
    Map<String, String> jmeterProps = new HashMap<>();
    if (argsTable == null) {
      return jmeterProps;
    }

    for (List<String> row : argsTable.asLists()) {
      if (row == null || row.isEmpty()) {
        continue;
      }
      parseJMeterPropertyRow(jmeterProps, row);
    }
    return jmeterProps;
  }

  /**
   * Parses one CLI-like table row into the mutable property map.
   *
   * @param jmeterProps target property map
   * @param row         argument table row
   */
  private void parseJMeterPropertyRow(Map<String, String> jmeterProps, List<String> row) {
    String flag = row.get(0) != null ? row.get(0).trim() : "";
    String value = row.size() > 1 && row.get(1) != null ? row.get(1).trim() : "";
    value = resolveTigerPlaceholders(value);

    if (flag.isEmpty()) {
      return;
    }

    switch (flag) {
      case "-l" -> {
        if (!value.isEmpty()) {
          jmeterProps.put("__JTL_OUTPUT__", value);
        }
      }
      case "-o", "-q", "-e" -> throw new AssertionError("Unsupported JMeter flag for DSL plan: " + flag);
      case "-f" -> jmeterProps.put("__OVERWRITE_JTL__", "true");
      default -> parseJMeterProperty(jmeterProps, flag, value);
    }
  }

  /**
   * Parses one {@code -J} property argument.
   *
   * @param jmeterProps target property map
   * @param flag        table flag
   * @param value       table value
   */
  private void parseJMeterProperty(Map<String, String> jmeterProps, String flag, String value) {
    if (!flag.startsWith("-J")) {
      throw new AssertionError("Unsupported JMeter flag for DSL plan: " + flag);
    }
    String propertySpec = flag.contains("=") ? flag : (flag + "=" + value);
    String propertyPart = propertySpec.substring(2);

    String[] parts = propertyPart.split("=", 2);
    if (parts.length == 2) {
      String key = parts[0];
      String val = parts[1];

      jmeterProps.put(key, val);
      log.debug("Added JMeter property: {}={}", key, val);
    }
  }

  /**
   * Stops an optional background reset thread.
   *
   * @param backgroundResetThread reset thread or {@code null}
   * @param backgroundResetStop   stop signal
   */
  private void stopBackgroundReset(Thread backgroundResetThread, AtomicBoolean backgroundResetStop) {
    if (backgroundResetThread == null) {
      return;
    }
    backgroundResetStop.set(true);
    try {
      backgroundResetThread.join(Duration.ofSeconds(5));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      log.warn("Interrupted while waiting for background reset thread to stop");
    }
  }

  /**
   * Cleans up load-driver instances and temporary binding files.
   *
   * @param loadDriverContext load-driver runtime context or {@code null}
   */
  private void cleanupLoadDriver(LoadDriverContext loadDriverContext) {
    if (loadDriverContext == null) {
      return;
    }
    if (loadDriverContext.cleanupAfterTest()) {
      loadDriverPreparationService.deleteAllInstances(
          loadDriverContext.client(), loadDriverContext.baseUrl());
    }
    loadDriverPreparationService.deleteInstancePathsFileQuietly(loadDriverContext.instancePathsFile());
  }
}
