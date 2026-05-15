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

import static us.abstracta.jmeter.javadsl.JmeterDsl.csvDataSet;
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
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import us.abstracta.jmeter.javadsl.core.DslTestPlan.TestPlanChild;
import us.abstracta.jmeter.javadsl.core.TestPlanStats;
import us.abstracta.jmeter.javadsl.core.configs.DslCsvDataSet;
import us.abstracta.jmeter.javadsl.core.preprocessors.DslJsr223PreProcessor.PreProcessorScript;
import us.abstracta.jmeter.javadsl.core.samplers.BaseSampler.SamplerChild;
import us.abstracta.jmeter.javadsl.core.threadgroups.BaseThreadGroup.ThreadGroupChild;

/**
 * JMeter DSL plan for PDP authenticate/removeAuth cycle load tests
 * (replaces pdp-auth-cycle-test.jmx).
 *
 * <p>Each thread runs a closed authenticate/removeAuth cycle.
 */
@Slf4j
@Builder
public class PdpAuthCyclePlan {

  private final String baseUrl;
  private final int threads;
  private final int rampSeconds;
  private final int durationSeconds;
  private final int targetRps;
  private final int jitterRangeMs;
  private final Path instancePathsFile;
  private final boolean oneInstancePerThread;
  private final Path jtlOutput;

  /**
   * Runs the PDP auth-cycle plan and returns the stats.
   */
  public TestPlanStats run() throws IOException {
    log.info(
        "Starting PDP auth-cycle plan: baseUrl={}, threads={}, duration={}s, targetRps={}",
        baseUrl, threads, durationSeconds, targetRps);

    List<ThreadGroupChild> threadGroupChildren = new ArrayList<>();

    configureInstancePathBinding(threadGroupChildren);

    var authenticateSampler = httpSampler("PDP Authenticate", "${path_authenticate}")
        .method("GET")
        .followRedirects(true)
        .children(buildAuthenticateChildren());

    // removeAuth sampler
    var removeAuthSampler = httpSampler("PDP RemoveAuth", "${path_remove_auth}")
        .method("GET")
        .followRedirects(true);

    threadGroupChildren.add(removeAuthSampler);
    threadGroupChildren.add(authenticateSampler);

    List<TestPlanChild> planElements = new ArrayList<>();
    planElements.add(httpDefaults()
        .url(baseUrl)
        .connectionTimeout(Duration.ofSeconds(10))
        .responseTimeout(Duration.ofSeconds(30)));
    planElements.add(
        threadGroup("PDP Auth Cycle")
            .rampToAndHold(
                threads,
                Duration.ofSeconds(rampSeconds),
                Duration.ofSeconds(durationSeconds))
            .children(threadGroupChildren.toArray(ThreadGroupChild[]::new)));

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
    List<String> instancePaths = loadInstancePaths();
    if (oneInstancePerThread) {
      validateOneInstancePerThreadCapacity(instancePaths);
      threadGroupChildren.add(jsr223PreProcessor(
          "Bind Instance Path",
          buildThreadBindingScript(instancePaths)));
      return;
    }

    Path authCsvFile = buildAuthCsvFile(instancePaths);
    threadGroupChildren.add(csvDataSet(authCsvFile.toAbsolutePath().toString())
        .variableNames("path_authenticate", "path_remove_auth")
        .sharedIn(DslCsvDataSet.Sharing.ALL_THREADS)
        .randomOrder(false));
  }

  /**
   * Builds sampler children for the authenticate request.
   *
   * @return authenticate sampler children in execution order
   */
  private SamplerChild[] buildAuthenticateChildren() {
    List<SamplerChild> children = new ArrayList<>();
    if (targetRps > 0) {
      children.add(throughputTimer(targetRps * 60.0));
    }

    if (jitterRangeMs > 0) {
      children.add(uniformRandomTimer(Duration.ZERO, Duration.ofMillis(jitterRangeMs)));
    }
    return children.toArray(SamplerChild[]::new);
  }

  /**
   * Writes an auxiliary CSV with authenticate/removeAuth paths derived from the instance list.
   *
   * @param instancePaths source instance paths
   * @return generated CSV file
   * @throws IOException when the CSV file cannot be written
   */
  private Path buildAuthCsvFile(List<String> instancePaths) throws IOException {
    List<String> csvLines = instancePaths.stream()
        .map(this::buildAuthCsvLine)
        .collect(Collectors.toList());
    Path csvFile = Files.createTempFile("pdp-auth-cycle-", ".csv");
    csvFile.toFile().deleteOnExit();
    Files.write(csvFile, csvLines, StandardCharsets.UTF_8);
    return csvFile;
  }

  /**
   * Loads non-empty instance paths from the prepared instance-path file.
   *
   * @return normalized list of configured instance paths
   * @throws IOException when the instance-path file cannot be read
   */
  private List<String> loadInstancePaths() throws IOException {
    if (instancePathsFile == null || !Files.exists(instancePathsFile)) {
      throw new IllegalStateException(
          "Instance paths file is required for PDP auth-cycle plan: " + instancePathsFile);
    }
    List<String> lines = Files.readAllLines(instancePathsFile, StandardCharsets.UTF_8).stream()
        .map(String::trim)
        .filter(line -> !line.isEmpty())
        .toList();
    if (lines.isEmpty()) {
      throw new IllegalStateException(
          "Instance paths file is empty: " + instancePathsFile);
    }
    return lines;
  }

  /**
   * Validates that closed-model execution still has one prepared instance per active thread.
   *
   * @param instancePaths available instance paths
   */
  private void validateOneInstancePerThreadCapacity(List<String> instancePaths) {
    if (threads > instancePaths.size()) {
      throw new IllegalStateException(
          "LOAD_ONE_INSTANCE_PER_THREAD=true requires THREADS <= available instance paths. "
              + "threads=" + threads + ", instancePaths=" + instancePaths.size());
    }
  }

  /**
   * Builds a Java-based pre-processor that binds one fixed instance path to each thread.
   *
   * @param instancePaths available instance paths indexed by thread number
   * @return pre-processor script for per-thread binding
   */
  private PreProcessorScript buildThreadBindingScript(List<String> instancePaths) {
    return vars -> {
      int threadIndex = vars.ctx.getThreadNum();
      if (threadIndex >= instancePaths.size()) {
        throw new IllegalStateException(
            "No instance path for thread index " + (threadIndex + 1)
                + "; paths=" + instancePaths.size());
      }
      String authPath = instancePaths.get(threadIndex);
      String basePath = normalizeInstanceBasePath(authPath);
      vars.vars.put("path_authenticate", basePath + "/authenticate");
      vars.vars.put("path_remove_auth", basePath + "/removeAuth");
    };
  }

  /**
   * Builds one CSV line containing authenticate/removeAuth paths for the given instance path.
   *
   * @param instancePath prepared instance path from the load driver
   * @return CSV line with authenticate and removeAuth paths
   */
  private String buildAuthCsvLine(String instancePath) {
    String basePath = normalizeInstanceBasePath(instancePath);
    return basePath + "/authenticate," + basePath + "/removeAuth";
  }

  /**
   * Normalizes an instance path to the base path used for authenticate/removeAuth derivation.
   *
   * @param instancePath prepared instance path from the load driver
   * @return normalized base path without trailing authenticate segment
   */
  private String normalizeInstanceBasePath(String instancePath) {
    if (instancePath.endsWith("/authenticate")) {
      return instancePath.substring(0, instancePath.length() - "/authenticate".length());
    }
    int lastSlash = instancePath.lastIndexOf('/');
    return lastSlash >= 0 ? instancePath.substring(0, lastSlash) : instancePath;
  }
}
