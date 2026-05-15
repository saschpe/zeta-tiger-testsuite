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
import de.gematik.zeta.steps.ReportAttachments;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

/**
 * Starts JMeter DSL plans in an isolated PlanRunner JVM.
 */
@Slf4j
public class PlanRunnerService {

  private static final ObjectMapper JSON = new ObjectMapper();

  /**
   * Dispatches to the appropriate JMeter DSL plan class based on the plan path identifier.
   */
  public void runDslPlan(
      String planPath,
      String baseUrl,
      int targetRps,
      Map<String, String> props) throws Exception {
    failOnUnsupportedDslProperties(props);
    deleteExistingJtlWhenRequested(props);

    Path argFile = null;
    Path requestFile = null;
    try {
      argFile = Files.createTempFile("planrunner-cp-", ".txt");
      requestFile = Files.createTempFile("planrunner-req-", ".json");
      argFile.toFile().deleteOnExit();
      requestFile.toFile().deleteOnExit();

      var quotedCp = Arrays.stream(System.getProperty("java.class.path").split(
              Pattern.quote(File.pathSeparator)))
          .map(entry -> "\"" + entry.replace("\\", "\\\\") + "\"")
          .collect(Collectors.joining(File.pathSeparator));
      Files.writeString(argFile, "-cp " + quotedCp);

      var request = new PlanRequest(planPath, baseUrl, targetRps, props);
      Files.writeString(requestFile, JSON.writeValueAsString(request), StandardCharsets.UTF_8);

      var command = List.of(
          Path.of(System.getProperty("java.home"), "bin", "java").toString(),
          "@" + argFile.toAbsolutePath(),
          "de.gematik.zeta.perf.PlanRunner",
          requestFile.toAbsolutePath().toString());

      log.info("Launching PlanRunner subprocess for plan: {}", planPath);
      var process = new ProcessBuilder(command)
          .redirectErrorStream(false)
          .start();

      var planRunnerLogDir = Path.of("target", "planrunner-logs");
      Files.createDirectories(planRunnerLogDir);
      var planRunnerLogStem =
          planPath.replaceAll("[^a-zA-Z0-9._-]", "_")
              + "-"
              + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").format(LocalDateTime.now());
      var stdoutLog = planRunnerLogDir.resolve(planRunnerLogStem + "-stdout.log");
      var stderrLog = planRunnerLogDir.resolve(planRunnerLogStem + "-stderr.log");

      var stdoutThread = createPlanRunnerLogThread(
          process.getInputStream(),
          stdoutLog,
          false,
          "planrunner-stdout");
      var stderrThread = createPlanRunnerLogThread(
          process.getErrorStream(),
          stderrLog,
          true,
          "planrunner-stderr");
      stdoutThread.start();
      stderrThread.start();

      final var exitCode = process.waitFor();
      stdoutThread.join();
      stderrThread.join();

      log.info("PlanRunner stdout log: {}", stdoutLog.toAbsolutePath());
      log.info("PlanRunner stderr log: {}", stderrLog.toAbsolutePath());
      attachPlanRunnerArtifacts(planPath, stdoutLog, stderrLog, resolveJtlOutputPath(props));
      if (exitCode != 0) {
        throw new AssertionError(
            "JMeter DSL plan failed (exit code " + exitCode + ") for plan: " + planPath);
      }
    } finally {
      deleteTempFileQuietly(argFile);
      deleteTempFileQuietly(requestFile);
    }
    log.info("PlanRunner finished successfully for plan: {}", planPath);
  }

  /**
   * Resolves the configured JMeter JTL output path from the plan properties.
   *
   * @param props JMeter property map
   * @return configured JTL path, or {@code null} when no output was requested
   */
  private Path resolveJtlOutputPath(Map<String, String> props) {
    var jtlPath = props.get("__JTL_OUTPUT__");
    if (jtlPath == null || jtlPath.isBlank()) {
      return null;
    }
    return Path.of(jtlPath).toAbsolutePath().normalize();
  }

  /**
   * Adds PlanRunner logs and JTL results to the scenario report.
   *
   * @param planPath plan identifier
   * @param stdoutLog PlanRunner stdout log
   * @param stderrLog PlanRunner stderr log
   * @param jtlOutput JMeter JTL output file
   */
  private void attachPlanRunnerArtifacts(
      String planPath,
      Path stdoutLog,
      Path stderrLog,
      Path jtlOutput) {
    ReportAttachments.addFile("JMeter PlanRunner stdout - " + planPath, stdoutLog, "text/plain");
    ReportAttachments.addFile("JMeter PlanRunner stderr - " + planPath, stderrLog, "text/plain");
    if (jtlOutput == null || !Files.exists(jtlOutput)) {
      return;
    }

    try {
      ReportAttachments.addText("JMeter JTL summary - " + planPath, buildJtlSummary(jtlOutput));
    } catch (IOException | IllegalArgumentException e) {
      ReportAttachments.addText(
          "JMeter JTL summary - " + planPath,
          "Could not read JTL file '" + jtlOutput + "': " + e.getMessage());
    }
  }

  /**
   * Builds a compact human-readable summary from a JMeter CSV/JTL result file.
   *
   * @param jtlOutput JMeter CSV/JTL result file
   * @return summary text for the report
   * @throws IOException when the JTL file cannot be read
   */
  private String buildJtlSummary(Path jtlOutput) throws IOException {
    var elapsedValues = new ArrayList<Long>();
    Map<String, Integer> responseCodes = new TreeMap<>();
    long minTimestamp = Long.MAX_VALUE;
    long maxEndTimestamp = Long.MIN_VALUE;
    int samples = 0;
    int errors = 0;

    try (var reader = Files.newBufferedReader(jtlOutput, StandardCharsets.UTF_8);
        var parser = CSVFormat.DEFAULT.builder()
            .setHeader()
            .setSkipHeaderRecord(true)
            .get()
            .parse(reader)) {
      for (CSVRecord record : parser) {
        samples++;
        var elapsed = parseJtlLong(record, "elapsed");
        var timestamp = parseJtlLong(record, "timeStamp");
        elapsedValues.add(elapsed);
        minTimestamp = Math.min(minTimestamp, timestamp);
        maxEndTimestamp = Math.max(maxEndTimestamp, timestamp + elapsed);
        if (!Boolean.parseBoolean(record.get("success"))) {
          errors++;
        }
        responseCodes.merge(record.get("responseCode"), 1, Integer::sum);
      }
    }

    elapsedValues.sort(Long::compareTo);
    var durationSeconds = samples == 0 || minTimestamp == Long.MAX_VALUE
        ? 0d
        : Math.max(0d, (maxEndTimestamp - minTimestamp) / 1000d);
    var throughput = durationSeconds > 0d ? samples / durationSeconds : 0d;
    var errorRate = samples > 0 ? errors * 100d / samples : 0d;
    var avgElapsed = elapsedValues.stream().mapToLong(Long::longValue).average().orElse(0d);
    var maxElapsed = elapsedValues.isEmpty() ? 0L : elapsedValues.get(elapsedValues.size() - 1);

    return String.format(
        java.util.Locale.ROOT,
        "file=%s%nsamples=%d%nerrors=%d%nerrorRate=%.2f%%%ndurationSeconds=%.2f%nthroughput=%.2f/s%n"
            + "elapsedMs={avg=%.1f,p90=%d,p95=%d,p99=%d,max=%d}%nresponseCodes=%s",
        jtlOutput,
        samples,
        errors,
        errorRate,
        durationSeconds,
        throughput,
        avgElapsed,
        percentileNearestRank(elapsedValues, 0.90d),
        percentileNearestRank(elapsedValues, 0.95d),
        percentileNearestRank(elapsedValues, 0.99d),
        maxElapsed,
        responseCodes);
  }

  /**
   * Parses a positive or zero long value from one JTL CSV record.
   *
   * @param record CSV record
   * @param column column name
   * @return parsed long value
   */
  private long parseJtlLong(CSVRecord record, String column) {
    var value = record.get(column);
    if (value == null || value.isBlank()) {
      return 0L;
    }
    return Long.parseLong(value.trim());
  }

  /**
   * Calculates a nearest-rank percentile from sorted values.
   *
   * @param sortedValues ascending values
   * @param percentile percentile in the range {@code 0..1}
   * @return percentile value, or {@code 0} for an empty input
   */
  private long percentileNearestRank(List<Long> sortedValues, double percentile) {
    if (sortedValues.isEmpty()) {
      return 0L;
    }
    var rankIndex = (int) Math.ceil(percentile * sortedValues.size()) - 1;
    var boundedIndex = Math.max(0, Math.min(rankIndex, sortedValues.size() - 1));
    return sortedValues.get(boundedIndex);
  }

  /**
   * Deletes one temporary PlanRunner input file without masking the original result.
   *
   * @param path temporary file path, or {@code null} when creation failed
   */
  private void deleteTempFileQuietly(Path path) {
    if (path == null) {
      return;
    }
    try {
      Files.deleteIfExists(path);
    } catch (IOException e) {
      log.warn("Could not delete PlanRunner temporary file {}: {}", path, e.getMessage());
    }
  }

  /**
   * Deletes a pre-existing JTL output file when overwrite mode is configured.
   *
   * @param props JMeter property map
   */
  private void deleteExistingJtlWhenRequested(Map<String, String> props) {
    if (!"true".equals(props.get("__OVERWRITE_JTL__"))) {
      return;
    }
    var jtlPath = props.get("__JTL_OUTPUT__");
    if (jtlPath == null || jtlPath.isBlank()) {
      return;
    }
    var jtl = Path.of(jtlPath);
    try {
      Files.deleteIfExists(jtl);
      log.info("Deleted existing JTL file (overwrite mode): {}", jtl.toAbsolutePath());
    } catch (Exception e) {
      log.warn("Could not delete JTL file {}: {}", jtl, e.getMessage());
    }
  }

  /**
   * Creates one thread that mirrors a PlanRunner stream to a persistent file and logger.
   *
   * @param stream process stream to consume
   * @param logFile target file for stream output
   * @param stderr whether the stream represents stderr
   * @param threadName thread name for diagnostics
   * @return configured but not yet started thread
   */
  private Thread createPlanRunnerLogThread(
      java.io.InputStream stream,
      Path logFile,
      boolean stderr,
      String threadName) {
    return new Thread(() -> {
      try (var reader = new BufferedReader(new InputStreamReader(stream));
          var writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8)) {
        String line;
        while ((line = reader.readLine()) != null) {
          writer.write(line);
          writer.newLine();
          writer.flush();
          if (stderr) {
            log.warn("[PlanRunner] {}", line);
          } else {
            log.info("[PlanRunner] {}", line);
          }
        }
      } catch (IOException e) {
        log.warn(
            "PlanRunner {} stream closed: {}",
            stderr ? "stderr" : "stdout",
            e.getMessage());
      }
    }, threadName);
  }

  /**
   * Rejects legacy JMeter CLI properties that are not supported by the Java DSL plans.
   *
   * @param props JMeter property map
   */
  private void failOnUnsupportedDslProperties(Map<String, String> props) {
    var unsupportedKeys = List.of(
        "WARMUP_S",
        "WARMUP_THREADS",
        "CONTENT_TYPE",
        "HEADER1_NAME",
        "HEADER1_VALUE",
        "HEADER2_NAME",
        "HEADER2_VALUE",
        "HEADER3_NAME",
        "HEADER3_VALUE");
    for (var key : unsupportedKeys) {
      if (props.containsKey(key)) {
        throw new AssertionError(
            "Unsupported JMeter property for DSL plan: " + key);
      }
    }
  }
}
