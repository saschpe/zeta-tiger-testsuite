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

package de.gematik.zeta.perf;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import us.abstracta.jmeter.javadsl.core.TestPlanStats;

/**
 * Entry point for running JMeter DSL plans in an isolated subprocess.
 *
 * <p>Accepts a single JSON argument serialized as a {@link PlanRequest}.
 * Exits with code 0 on success, 1 on assertion failures, 2 on unexpected errors.
 */
@Slf4j
public class PlanRunner {

  /**
   * Starts the subprocess entry point for a serialized {@link PlanRequest}.
   *
   * @param args exactly one path to the JSON request file
   */
  public static void main(String[] args) {
    if (args.length != 1) {
      log.error("Usage: PlanRunner <path-to-plan-request.json>");
      System.exit(2);
    }

    PlanRequest request;
    try {
      request = new ObjectMapper().readValue(
          Path.of(args[0]).toFile(),
          PlanRequest.class);
    } catch (Exception e) {
      log.error("Failed to parse PlanRequest JSON: {}", e.getMessage());
      System.exit(2);
      return;
    }

    try {
      TestPlanStats stats = runPlan(request);
      log.info("Plan finished: samples={}, errors={}",
          stats.overall().samplesCount(), stats.overall().errorsCount());
      System.exit(0);
    } catch (AssertionError e) {
      log.error("Plan assertion failed", e);
      System.exit(1);
    } catch (Exception e) {
      log.error("Plan execution failed", e);
      System.exit(2);
    }
  }

  /**
   * Builds and executes the selected JMeter DSL plan for the request.
   *
   * @param req plan execution request
   * @return aggregated plan statistics
   * @throws Exception when plan selection or execution fails
   */
  private static TestPlanStats runPlan(PlanRequest req) throws Exception {
    Map<String, String> props =
        req.props() != null ? req.props() : Collections.emptyMap();
    String planId = req.planId();
    if (planId == null || planId.isBlank()) {
      throw new IllegalArgumentException("PlanRequest.planId must not be null or blank");
    }
    if (req.baseUrl() == null || req.baseUrl().isBlank()) {
      throw new IllegalArgumentException("PlanRequest.baseUrl must not be null or blank");
    }

    int threads = parsePositiveInt(props, "THREADS", 1);
    int rampS = parsePositiveInt(props, "RAMP_S", 5);
    int durationS = parsePositiveInt(props, "DURATION_S", 30);
    int jitterMs = parsePositiveInt(props, "JITTER_RANGE_MS", 0);
    Path instancePathsFile = props.containsKey("INSTANCE_PATHS_FILE")
        ? Path.of(props.get("INSTANCE_PATHS_FILE")) : null;
    Path jtlOutput = props.containsKey("__JTL_OUTPUT__")
        ? Path.of(props.get("__JTL_OUTPUT__")) : null;

    return switch (planId) {
      case "parameterized-http-test" -> {
        boolean onePerThread = Boolean.parseBoolean(
            props.getOrDefault("LOAD_ONE_INSTANCE_PER_THREAD", "false"));
        String method = props.getOrDefault("HTTP_METHOD", "GET");

        boolean hasPoppToken = Boolean.parseBoolean(
            props.getOrDefault("INSTANCE_PATHS_HAS_POPP_TOKEN", "false"));

        yield ParameterizedHttpPlan.builder()
            .baseUrl(req.baseUrl())
            .httpMethod(method)
            .threads(threads)
            .rampSeconds(rampS)
            .durationSeconds(durationS)
            .targetRps(req.targetRps())
            .jitterRangeMs(jitterMs)
            .instancePathsFile(instancePathsFile)
            .oneInstancePerThread(onePerThread)
            .hasPoppToken(hasPoppToken)
            .jtlOutput(jtlOutput)
            .build()
            .run();
      }
      case "pdp-auth-cycle-test" -> {
        boolean onePerThread = Boolean.parseBoolean(
            props.getOrDefault("LOAD_ONE_INSTANCE_PER_THREAD", "false"));

        yield PdpAuthCyclePlan.builder()
            .baseUrl(req.baseUrl())
            .threads(threads)
            .rampSeconds(rampS)
            .durationSeconds(durationS)
            .targetRps(req.targetRps())
            .jitterRangeMs(jitterMs)
            .instancePathsFile(instancePathsFile)
            .oneInstancePerThread(onePerThread)
            .jtlOutput(jtlOutput)
            .build()
            .run();
      }
      default -> throw new IllegalArgumentException("Unknown plan id: " + planId);
    };
  }

  /**
   * Parses a positive integer property and falls back for blank, missing or non-positive values.
   *
   * @param props source property map
   * @param key property key
   * @param fallback fallback value
   * @return parsed positive integer or fallback
   */
  private static int parsePositiveInt(Map<String, String> props, String key, int fallback) {
    String val = props.get(key);
    if (val == null || val.isBlank()) {
      return fallback;
    }
    try {
      int parsed = Integer.parseInt(val.trim());
      if (parsed <= 0) {
        throw new IllegalArgumentException(
            "Invalid non-positive integer value for property '" + key + "': '" + val + "'");
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "Invalid integer value for property '" + key + "': '" + val + "'", e);
    }
  }
}
