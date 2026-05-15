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

import static us.abstracta.jmeter.javadsl.JmeterDsl.httpDefaults;
import static us.abstracta.jmeter.javadsl.JmeterDsl.httpSampler;
import static us.abstracta.jmeter.javadsl.JmeterDsl.jsr223PreProcessor;
import static us.abstracta.jmeter.javadsl.JmeterDsl.jtlWriter;
import static us.abstracta.jmeter.javadsl.JmeterDsl.testPlan;
import static us.abstracta.jmeter.javadsl.JmeterDsl.threadGroup;
import static us.abstracta.jmeter.javadsl.JmeterDsl.throughputTimer;
import static us.abstracta.jmeter.javadsl.JmeterDsl.uniformRandomTimer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import us.abstracta.jmeter.javadsl.core.DslTestPlan.TestPlanChild;
import us.abstracta.jmeter.javadsl.core.TestPlanStats;
import us.abstracta.jmeter.javadsl.core.preprocessors.DslJsr223PreProcessor.PreProcessorScript;
import us.abstracta.jmeter.javadsl.core.threadgroups.BaseThreadGroup.ThreadGroupChild;

/**
 * JMeter DSL plan for parameterized HTTP load tests (replaces parameterized-http-test.jmx).
 *
 * <p>Supports shared or per-thread instance-path binding with throughput pacing.
 */
@Slf4j
@Builder
public class ParameterizedHttpPlan {

  private final String baseUrl;
  private final String httpMethod;
  private final int threads;
  private final int rampSeconds;
  private final int durationSeconds;
  private final int targetRps;
  private final int jitterRangeMs;
  private final Path instancePathsFile;
  private final boolean oneInstancePerThread;
  private final boolean hasPoppToken;
  private final Path jtlOutput;

  private static final String ROTATION_COUNTER_PROPERTY =
      ParameterizedHttpPlan.class.getName() + ".rotationCounter";

  /**
   * Runs the test plan and returns the stats.
   */
  public TestPlanStats run() throws IOException {
    log.info(
        "Starting parameterized HTTP plan: baseUrl={}, threads={}, duration={}s, targetRps={}",
        baseUrl, threads, durationSeconds, targetRps);
    requireInstancePathsFile();

    List<TestPlanChild> planElements = new ArrayList<>();

    // Set base URL for all samplers so ${instance_path} is resolved as relative path at runtime
    planElements.add(httpDefaults()
        .url(baseUrl)
        .connectionTimeout(Duration.ofSeconds(10))
        .responseTimeout(Duration.ofSeconds(30)));

    // Load test thread group
    List<ThreadGroupChild> loadChildren = new ArrayList<>();

    configureInstancePathBinding(loadChildren);

    var sampler = httpSampler("ZetaGuard Request", "${instance_path}")
        .method(httpMethod)
        .followRedirects(true);
    if (hasPoppToken) {
      sampler.header("PoPP", "${popp_token}");
    }
    loadChildren.add(sampler);

    if (targetRps > 0) {
      loadChildren.add(throughputTimer(targetRps * 60.0));
    }

    if (jitterRangeMs > 0) {
      loadChildren.add(uniformRandomTimer(Duration.ZERO, Duration.ofMillis(jitterRangeMs)));
    }

    planElements.add(
        threadGroup("Load Test")
            .rampToAndHold(
                threads,
                Duration.ofSeconds(rampSeconds),
                Duration.ofSeconds(durationSeconds))
            .children(loadChildren.toArray(ThreadGroupChild[]::new)));

    if (jtlOutput != null) {
      var normalizedJtl = jtlOutput.toAbsolutePath().normalize();
      var parent = normalizedJtl.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      var outputDir = parent != null ? parent.toString() : ".";
      var outputFile = normalizedJtl.getFileName().toString();
      planElements.add(jtlWriter(outputDir, outputFile));
    }

    return testPlan(planElements.toArray(TestPlanChild[]::new)).run();
  }

  /**
   * Configures the instance-path source for the thread group.
   *
   * @param threadGroupChildren target list for thread group children
   * @throws IOException when reading or preparing instance-path data fails
   */
  private void configureInstancePathBinding(List<ThreadGroupChild> threadGroupChildren)
      throws IOException {
    List<String[]> rows = loadInstancePathRows();
    if (oneInstancePerThread) {
      validateOneInstancePerThreadCapacity(rows);
      threadGroupChildren.add(jsr223PreProcessor(
          "Bind Instance Path",
          buildThreadBindingScript(rows)));
      return;
    }

    threadGroupChildren.add(jsr223PreProcessor(
        "Rotate Instance Path",
        buildSharedRotationScript(rows)));
  }

  /**
   * Loads data rows from the instance-paths file, skipping the header line when present.
   * Each row is a String[] where index 0 = instance_path, index 1 = popp_token (optional).
   */
  private List<String[]> loadInstancePathRows() throws IOException {
    if (instancePathsFile == null || !Files.exists(instancePathsFile)) {
      throw new IllegalStateException(
          "Instance paths file is required for parameterized HTTP plan: " + instancePathsFile);
    }
    List<String> lines = Files.readAllLines(instancePathsFile, StandardCharsets.UTF_8).stream()
        .map(String::trim)
        .filter(line -> !line.isEmpty())
        .toList();
    if (lines.isEmpty()) {
      throw new IllegalStateException("Instance paths file is empty: " + instancePathsFile);
    }
    int start = hasPoppToken ? 1 : 0; // skip header row written by writeInstancePathsFileWithPoppTokens
    List<String[]> rows = new ArrayList<>();
    for (int i = start; i < lines.size(); i++) {
      rows.add(lines.get(i).split(",", 2));
    }
    if (rows.isEmpty()) {
      throw new IllegalStateException("Instance paths file has no data rows: " + instancePathsFile);
    }
    return rows;
  }

  private void validateOneInstancePerThreadCapacity(List<String[]> rows) {
    if (threads > rows.size()) {
      throw new IllegalStateException(
          "LOAD_ONE_INSTANCE_PER_THREAD=true requires THREADS <= available instance paths. "
              + "threads=" + threads + ", instancePaths=" + rows.size());
    }
  }

  private PreProcessorScript buildThreadBindingScript(List<String[]> rows) {
    return vars -> {
      int threadIndex = vars.ctx.getThreadNum();
      if (threadIndex >= rows.size()) {
        throw new IllegalStateException(
            "No instance path for thread index " + (threadIndex + 1)
                + "; paths=" + rows.size());
      }
      String[] row = rows.get(threadIndex);
      vars.vars.put("instance_path", row[0]);
      if (hasPoppToken && row.length > 1) {
        vars.vars.put("popp_token", row[1]);
      }
    };
  }

  /**
   * Builds a pre-processor that advances through prepared rows globally across all threads while
   * keeping {@code instance_path} and {@code popp_token} bound to the same CSV row.
   *
   * @param rows prepared instance/path rows
   * @return pre-processor script for shared rotation
   */
  private PreProcessorScript buildSharedRotationScript(List<String[]> rows) {
    return vars -> {
      AtomicInteger counter = lookupOrCreateRotationCounter(vars);
      int index = Math.floorMod(counter.getAndIncrement(), rows.size());
      bindRow(vars, rows.get(index));
    };
  }

  /**
   * Resolves the global shared counter used for all-thread rotation, creating it on first access.
   *
   * @param vars JMeter script variables context
   * @return shared atomic counter
   */
  private AtomicInteger lookupOrCreateRotationCounter(
      us.abstracta.jmeter.javadsl.core.preprocessors.DslJsr223PreProcessor.PreProcessorVars vars) {
    synchronized (vars.props) {
      Object current = vars.props.get(ROTATION_COUNTER_PROPERTY);
      if (current instanceof AtomicInteger counter) {
        return counter;
      }
      AtomicInteger counter = new AtomicInteger(0);
      vars.props.put(ROTATION_COUNTER_PROPERTY, counter);
      return counter;
    }
  }

  /**
   * Binds one prepared row into the JMeter variable context.
   *
   * @param vars JMeter script variables context
   * @param row prepared row with instance path and optional PoPP token
   */
  private void bindRow(
      us.abstracta.jmeter.javadsl.core.preprocessors.DslJsr223PreProcessor.PreProcessorVars vars,
      String[] row) {
    vars.vars.put("instance_path", row[0]);
    if (hasPoppToken) {
      vars.vars.put("popp_token", row.length > 1 ? row[1] : "");
    }
  }

  /**
   * Ensures the plan has an instance-path file before building the sampler tree.
   */
  private void requireInstancePathsFile() {
    if (instancePathsFile == null) {
      throw new IllegalStateException(
          "INSTANCE_PATHS_FILE is required for parameterized HTTP plan.");
    }
  }
}
