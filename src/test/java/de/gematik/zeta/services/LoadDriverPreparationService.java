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

import static de.gematik.zeta.services.JMeterPropertySupport.DEFAULT_GUARD_TOKEN_PATH;
import static de.gematik.zeta.services.JMeterPropertySupport.DEFAULT_LOAD_PATH_TEMPLATE;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_INIT_BUFFER_TARGET_VAR;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_ONE_INSTANCE_PER_THREAD;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_POPP_TOKEN_GENERATOR_URL;
import static de.gematik.zeta.services.JMeterPropertySupport.LOAD_SMCB_KEYSTORE_MANIFEST;
import static de.gematik.zeta.services.JMeterPropertySupport.buildLoadInstancePath;
import static de.gematik.zeta.services.JMeterPropertySupport.ensureStartsWithSlash;
import static de.gematik.zeta.services.JMeterPropertySupport.normalizeBaseUrl;
import static de.gematik.zeta.services.JMeterPropertySupport.parseBoolean;
import static de.gematik.zeta.services.JMeterPropertySupport.parsePositiveInt;
import static de.gematik.zeta.services.JMeterPropertySupport.requireProperty;
import static de.gematik.zeta.services.JMeterPropertySupport.trimToNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.test.tiger.common.config.ConfigurationValuePrecedence;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.zeta.perf.PlanRunnerService;
import de.gematik.zeta.services.model.CreateBatchDescriptor;
import de.gematik.zeta.services.model.LoadDriverContext;
import de.gematik.zeta.services.model.LoadDriverSetupConfig;
import de.gematik.zeta.services.model.PoppPrefetch;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;

/**
 * Prepares load-driver instances and runs per-wave JMeter plans when requested.
 */
@Slf4j
public class LoadDriverPreparationService {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Set<String> LOAD_PROPERTIES_REQUIRED_BY_PLAN = Set.of(
      LOAD_ONE_INSTANCE_PER_THREAD);

  private final PlanRunnerService planRunnerService;
  private final LoadDriverClient loadDriverClient;
  private final LoadDriverCreateBodyFactory createBodyFactory;
  private final SmcbKeystoreRepository smcbKeystoreRepository;
  private final PoppTokenService poppTokenService;
  private final InstancePathBindingService bindingService;

  /**
   * Creates a service with default dependencies.
   */
  public LoadDriverPreparationService() {
    this(
        new PlanRunnerService(),
        new LoadDriverClient(),
        new LoadDriverCreateBodyFactory(),
        new SmcbKeystoreRepository(),
        new PoppTokenService(),
        new InstancePathBindingService());
  }

  /**
   * Creates a service with explicit dependencies.
   */
  public LoadDriverPreparationService(
      PlanRunnerService planRunnerService,
      LoadDriverClient loadDriverClient,
      LoadDriverCreateBodyFactory createBodyFactory,
      SmcbKeystoreRepository smcbKeystoreRepository,
      PoppTokenService poppTokenService,
      InstancePathBindingService bindingService) {
    this.planRunnerService = planRunnerService;
    this.loadDriverClient = loadDriverClient;
    this.createBodyFactory = createBodyFactory;
    this.smcbKeystoreRepository = smcbKeystoreRepository;
    this.poppTokenService = poppTokenService;
    this.bindingService = bindingService;
  }

  /**
   * Prepares load-driver instances and executes configured JMeter waves.
   */
  public LoadDriverContext prepare(Map<String, String> jmeterProps) throws Exception {
    var createBody = createBodyFactory.generateIfNeeded(
        jmeterProps,
        parsePositiveInt(jmeterProps.get("LOAD_INSTANCE_COUNT"), 1, "LOAD_INSTANCE_COUNT"),
        parseBoolean(jmeterProps.get("LOAD_AUTO_INIT"), true));
    var config = parseConfig(jmeterProps, createBody);

    var client = loadDriverClient.createHttpClient();
    if (config.cleanupBeforeCreate()) {
      loadDriverClient.deleteAllInstances(client, config.baseUrl());
    }

    jmeterProps.put("BASE_URL", config.baseUrl());
    removeLoadDriverControlProperties(jmeterProps);
    jmeterProps.put("__WAVES_DONE__", "true");

    log.info(
        "Load-driver wave setup: baseUrl={}, instancesPerWave={}, waves={}, autoInit={}, "
            + "waitReady={}, oneInstancePerClient={}, proxyPath={}, pathTemplate={}, "
            + "initPathTemplate={}",
        config.baseUrl(),
        config.instancesPerWave(),
        config.waves(),
        config.autoInit(),
        config.waitReady(),
        config.oneInstancePerClient(),
        config.proxyPath(),
        config.pathTemplate(),
        config.initPathTemplate());

    return runWaves(client, config, createBody, jmeterProps);
  }

  /**
   * Deletes all load-driver instances.
   */
  public void deleteAllInstances(HttpClient client, String loadDriverBaseUrl) {
    loadDriverClient.deleteAllInstances(client, loadDriverBaseUrl);
  }

  /**
   * Deletes a generated instance-path binding file.
   */
  public void deleteInstancePathsFileQuietly(Path path) {
    bindingService.deleteQuietly(path);
  }

  private LoadDriverContext runWaves(
      HttpClient client,
      LoadDriverSetupConfig config,
      String createBody,
      Map<String, String> jmeterProps) throws Exception {
    List<Integer> activeBackgroundResetIds = null;
    var poppPrefetchExecutor = Executors.newSingleThreadExecutor();
    try {
      var poppPrefetchFuture = startPoppPrefetchIfNeeded(config, poppPrefetchExecutor);

      List<Integer> resetModeIds = null;
      if (config.resetBetweenWaves()) {
        log.info("Reset mode: creating {} instances once upfront", config.instancesPerWave());
        resetModeIds = createInstancesForWave(client, config, createBody, 0);
        if (config.backgroundReset()) {
          activeBackgroundResetIds = List.copyOf(resetModeIds);
        }
        log.info("Reset mode: {} instances created, paths will be reused across all {} waves",
            resetModeIds.size(), config.waves());
      }

      var totalInitMs = 0L;
      Path waveInstancePathsFile = null;
      for (var wave = 0; wave < config.waves(); wave++) {
        final var waveStartedNanos = System.nanoTime();
        List<Integer> waveIds;
        var deleteMs = 0L;
        var createMs = 0L;

        if (config.resetBetweenWaves()) {
          waveIds = resetModeIds;
          if (wave > 0) {
            var resetStartedNanos = System.nanoTime();
            loadDriverClient.resetInstances(
                client, config.baseUrl(), waveIds, config.initPathTemplate(), config.initStepTimeout());
            deleteMs = Duration.ofNanos(System.nanoTime() - resetStartedNanos).toMillis();
            log.info("Wave {}/{}: reset {} instances in {}ms",
                wave + 1, config.waves(), waveIds.size(), deleteMs);
          } else {
            log.info("Wave {}/{}: first wave, skipping reset (instances freshly created)",
                wave + 1, config.waves());
          }
        } else {
          var manifestOffset = wave * config.instancesPerWave();
          log.info("Wave {}/{}: creating {} instances (manifest offset={})",
              wave + 1, config.waves(), config.instancesPerWave(), manifestOffset);

          if (wave > 0) {
            var deleteStartedNanos = System.nanoTime();
            loadDriverClient.deleteAllInstances(client, config.baseUrl());
            deleteMs = Duration.ofNanos(System.nanoTime() - deleteStartedNanos).toMillis();
          }

          var createStartedNanos = System.nanoTime();
          waveIds = createInstancesForWave(client, config, createBody, manifestOffset);
          createMs = Duration.ofNanos(System.nanoTime() - createStartedNanos).toMillis();
          if (config.backgroundReset()) {
            activeBackgroundResetIds = List.copyOf(waveIds);
          }
        }


        if (!config.resetBetweenWaves() || waveInstancePathsFile == null) {
          if (waveInstancePathsFile != null) {
            bindingService.deleteQuietly(waveInstancePathsFile);
          }
          var manifestOffset = config.resetBetweenWaves() ? 0 : wave * config.instancesPerWave();
          waveInstancePathsFile = prepareWaveBinding(
              config, jmeterProps, waveIds, wave, manifestOffset, poppPrefetchFuture);
          if (poppPrefetchFuture != null) {
            poppPrefetchFuture = null;
          }
        }
        jmeterProps.put("INSTANCE_PATHS_FILE", waveInstancePathsFile.toString());

        var hasPoppTokens = "true".equals(jmeterProps.get("INSTANCE_PATHS_HAS_POPP_TOKEN"));
        if (config.precheckEnabled() && !hasPoppTokens) {
          loadDriverClient.runPrecheck(
              client,
              config.baseUrl(),
              waveIds,
              config.proxyPath(),
              config.pathTemplate(),
              config.precheckMethod(),
              config.precheckSampleSize());
        }

        final var waveTargetRps = Integer.parseInt(jmeterProps.getOrDefault("TARGET_RPS", "300"));
        Map<String, String> waveProps = new HashMap<>(jmeterProps);
        waveProps.put("DURATION_S", Integer.toString(config.waveDurationSeconds()));

        var planPath = jmeterProps.get("__PLAN_PATH__");
        log.info("Wave {}/{}: running JMeter for {}s", wave + 1, config.waves(),
            config.waveDurationSeconds());
        var jmeterStartedNanos = System.nanoTime();
        planRunnerService.runDslPlan(planPath, config.baseUrl(), waveTargetRps, waveProps);
        var jmeterMs = Duration.ofNanos(System.nanoTime() - jmeterStartedNanos).toMillis();
        var waitReadyMs = waitForReadyIfNeeded(client, config, waveIds);
        var initFlowMs = runInitFlowIfNeeded(client, config, waveIds);

        totalInitMs += createMs + waitReadyMs + initFlowMs;
        var waveTotalMs = Duration.ofNanos(System.nanoTime() - waveStartedNanos).toMillis();
        log.info(
            "Wave {}/{} complete: ids={}, deleteMs={}, createMs={}, waitReadyMs={}, initMs={}, jmeterMs={}, totalMs={}",
            wave + 1, config.waves(), waveIds.size(), deleteMs, createMs, waitReadyMs, initFlowMs,
            jmeterMs, waveTotalMs);
      }

      writeInitBuffer(config, totalInitMs);

      return new LoadDriverContext(
          client,
          config.baseUrl(),
          config.cleanupAfterTest(),
          waveInstancePathsFile,
          activeBackgroundResetIds,
          config.initPathTemplate(),
          config.initStepTimeout());
    } finally {
      poppPrefetchExecutor.shutdownNow();
    }
  }

  private Future<PoppPrefetch> startPoppPrefetchIfNeeded(
      LoadDriverSetupConfig config, ExecutorService executor) {
    if (config.smcbManifest() == null
        || config.poppTokenGeneratorUrl() == null
        || config.resetBetweenWaves()) {
      return null;
    }
    log.info("Starting PoPP prefetch for {} instances in background", config.instancesPerWave());
    return executor.submit(() -> {
      var t0 = System.nanoTime();
      var entries = smcbKeystoreRepository.loadManifestEntries(
          Path.of(config.smcbManifest()).toAbsolutePath().normalize(), 0, config.instancesPerWave());
      var claims = poppTokenService.extractPoppClaims(entries);
      var tokens = poppTokenService.fetchPoppTokensBatch(
          loadDriverClient.createHttpClient(), config.poppTokenGeneratorUrl(), claims);
      log.info("PoPP prefetch completed in {}ms for {} tokens",
          Duration.ofNanos(System.nanoTime() - t0).toMillis(), tokens.size());
      return new PoppPrefetch(claims, tokens);
    });
  }

  private Path prepareWaveBinding(
      LoadDriverSetupConfig config,
      Map<String, String> jmeterProps,
      List<Integer> waveIds,
      int wave,
      int manifestOffset,
      Future<PoppPrefetch> poppPrefetchFuture) throws Exception {
    if (poppPrefetchFuture != null && manifestOffset == 0) {
      log.info("Wave {}/{}: waiting for PoPP prefetch result", wave + 1, config.waves());
      var waitT0 = System.nanoTime();
      var prefetched = poppPrefetchFuture.get();
      log.info("Wave {}/{}: PoPP prefetch ready after {}ms with {} tokens",
          wave + 1, config.waves(), Duration.ofNanos(System.nanoTime() - waitT0).toMillis(),
          prefetched.tokens().size());
      var paths = bindingService.buildInstancePaths(
          waveIds, config.proxyPath(), config.pathTemplate());
      if (config.persistPoppBindings()) {
        bindingService.persistPoppTokenBindings(
            config.baseUrl(), paths, prefetched.claims(), prefetched.tokens());
      }
      var file = bindingService.writeWithPoppTokens(paths, prefetched.tokens());
      jmeterProps.put("INSTANCE_PATHS_HAS_POPP_TOKEN", "true");
      jmeterProps.put("INSTANCE_PATHS_FILE", file.toString());
      log.info("Wave {}/{}: instance paths file written from PoPP prefetch: {}",
          wave + 1, config.waves(), file);
      return file;
    }

    restorePoppBindingProperties(jmeterProps, config.smcbManifest(), config.poppTokenGeneratorUrl());
    var binding = bindingService.prepare(
        waveIds,
        config.baseUrl(),
        config.proxyPath(),
        config.pathTemplate(),
        config.oneInstancePerClient(),
        config.loadThreads(),
        jmeterProps,
        manifestOffset,
        config.persistPoppBindings());
    if (binding.containsPoppToken()) {
      jmeterProps.put("INSTANCE_PATHS_HAS_POPP_TOKEN", "true");
    } else {
      jmeterProps.remove("INSTANCE_PATHS_HAS_POPP_TOKEN");
    }
    jmeterProps.put("INSTANCE_PATHS_FILE", binding.file().toString());
    removePoppBindingProperties(jmeterProps);
    return binding.file();
  }

  private long waitForReadyIfNeeded(
      HttpClient client, LoadDriverSetupConfig config, List<Integer> waveIds) throws Exception {
    if (!config.waitReady()) {
      return 0L;
    }
    var targetStates = config.autoInit() ? Set.of("READY") : Set.of("CREATED");
    var waitStartedNanos = System.nanoTime();
    loadDriverClient.waitForInstancesState(
        client, config.baseUrl(), waveIds, targetStates, config.readyTimeout(), config.readyPollInterval());
    return Duration.ofNanos(System.nanoTime() - waitStartedNanos).toMillis();
  }

  private long runInitFlowIfNeeded(
      HttpClient client, LoadDriverSetupConfig config, List<Integer> waveIds) throws Exception {
    if (config.initFlow().isEmpty()) {
      return 0L;
    }
    var initStartedNanos = System.nanoTime();
    loadDriverClient.runInitFlow(
        client, config.baseUrl(), waveIds, config.initPathTemplate(),
        config.initFlow(), config.initStepTimeout());
    return Duration.ofNanos(System.nanoTime() - initStartedNanos).toMillis();
  }

  private void writeInitBuffer(LoadDriverSetupConfig config, long totalInitMs) {
    if (config.initBufferTargetVar() == null) {
      return;
    }
    var initBufferS = totalInitMs / 1000 + 30;
    log.info("Writing initBufferS={} (totalInitMs={}) to Tiger variable '{}'",
        initBufferS, totalInitMs, config.initBufferTargetVar());
    TigerGlobalConfiguration.putValue(
        config.initBufferTargetVar(),
        String.valueOf(initBufferS),
        ConfigurationValuePrecedence.LOCAL_TEST_CASE_CONTEXT);
  }

  private List<Integer> createInstancesForWave(
      HttpClient client,
      LoadDriverSetupConfig config,
      String createBody,
      int manifestOffset) throws Exception {
    if (config.smcbManifest() != null) {
      return createLoadDriverInstancesFromSmcbManifest(
          client,
          config.baseUrl(),
          config.smcbManifest(),
          config.fachdienstUrl(),
          config.instancesPerWave(),
          config.autoInit(),
          manifestOffset,
          config.createBatchSize());
    }
    return createLoadDriverInstances(
        client,
        config.baseUrl(),
        config.instancesPerWave(),
        config.autoInit(),
        createBody,
        config.createBatchSize());
  }

  private List<Integer> createLoadDriverInstances(
      HttpClient client,
      String loadDriverBaseUrl,
      int instanceCount,
      boolean autoInit,
      String createBody,
      int createBatchSize) throws Exception {
    var effectiveBatchSize = Math.max(1, Math.min(createBatchSize, instanceCount));
    var createBodyRoot = trimToNull(createBody) == null ? null : JSON.readTree(createBody);

    var batches = new ArrayList<CreateBatchDescriptor>();
    for (var batchStart = 0; batchStart < instanceCount; batchStart += effectiveBatchSize) {
      var batchCount = Math.min(effectiveBatchSize, instanceCount - batchStart);
      var batchBody = createBodyFactory.buildBatch(
          createBodyRoot, createBody, batchStart, batchCount, autoInit);
      var uri = URI.create(loadDriverBaseUrl + "/load/create_instances?count=" + batchCount
          + "&autoInit=" + autoInit);
      batches.add(new CreateBatchDescriptor(batchCount, batchBody, uri));
    }
    return loadDriverClient.executeCreateBatches(client, instanceCount, batches);
  }

  private List<Integer> createLoadDriverInstancesFromSmcbManifest(
      HttpClient client,
      String loadDriverBaseUrl,
      String manifestPath,
      String fachdienstUrl,
      int instanceCount,
      boolean autoInit,
      int manifestStartIndex,
      int createBatchSize) throws Exception {
    smcbKeystoreRepository.validateManifestCreateInputs(manifestPath, fachdienstUrl);
    var entries = smcbKeystoreRepository.loadManifestEntries(
        Path.of(manifestPath).toAbsolutePath().normalize(), manifestStartIndex, instanceCount);
    if (entries.size() < instanceCount) {
      throw new AssertionError(
          "SMC-B keystore manifest " + manifestPath + " contains only "
              + entries.size() + " usable entries, but " + instanceCount
              + " instances were requested.");
    }

    var effectiveBatchSize = Math.max(1, Math.min(createBatchSize, instanceCount));
    var batches = new ArrayList<CreateBatchDescriptor>();
    for (var batchStart = 0; batchStart < instanceCount; batchStart += effectiveBatchSize) {
      var batchCount = Math.min(effectiveBatchSize, instanceCount - batchStart);
      var batchBody = createBodyFactory.fromSmcbEntries(
          entries.subList(batchStart, batchStart + batchCount), fachdienstUrl, autoInit);
      var uri = URI.create(
          loadDriverBaseUrl + "/load/create_instances?count=" + batchCount + "&autoInit=" + autoInit);
      batches.add(new CreateBatchDescriptor(batchCount, batchBody, uri));
    }
    return loadDriverClient.executeCreateBatches(client, instanceCount, batches);
  }

  private LoadDriverSetupConfig parseConfig(Map<String, String> jmeterProps, String createBody) {
    var loadDriverBaseUrl = normalizeBaseUrl(requireProperty(jmeterProps, "LOAD_DRIVER_BASE_URL"));
    var configuredInstanceCount = parsePositiveInt(
        jmeterProps.get("LOAD_INSTANCE_COUNT"), 1, "LOAD_INSTANCE_COUNT");
    var autoInit = parseBoolean(jmeterProps.get("LOAD_AUTO_INIT"), true);
    var cleanupBeforeCreate = parseBoolean(jmeterProps.get("LOAD_DELETE_BEFORE_CREATE"), true);
    var cleanupAfterTest = parseBoolean(jmeterProps.get("LOAD_DELETE_AFTER_TEST"), true);
    var waitReady = parseBoolean(jmeterProps.get("LOAD_WAIT_READY"), autoInit);
    var readyTimeoutSeconds = parsePositiveInt(
        jmeterProps.get("LOAD_READY_TIMEOUT_S"), 180, "LOAD_READY_TIMEOUT_S");
    var readyPollMs = parsePositiveInt(
        jmeterProps.get("LOAD_READY_POLL_MS"), 1000, "LOAD_READY_POLL_MS");
    var instanceCount = createBodyFactory.resolveExpectedInstanceCount(
        jmeterProps, createBody, configuredInstanceCount);
    var createBatchSize = parsePositiveInt(
        jmeterProps.get("LOAD_CREATE_BATCH_SIZE"), instanceCount, "LOAD_CREATE_BATCH_SIZE");
    var totalClients = parsePositiveInt(
        jmeterProps.get("LOAD_TOTAL_CLIENTS"), instanceCount, "LOAD_TOTAL_CLIENTS");
    var waveDurationS = parsePositiveInt(
        jmeterProps.get("LOAD_WAVE_DURATION_S"),
        parsePositiveInt(jmeterProps.get("DURATION_S"), 30, "DURATION_S"),
        "LOAD_WAVE_DURATION_S");
    var resetBetweenWaves = parseBoolean(jmeterProps.get("LOAD_RESET_BETWEEN_WAVES"), false);
    var backgroundReset = parseBoolean(jmeterProps.get("LOAD_BACKGROUND_RESET"), false);

    if (totalClients % instanceCount != 0) {
      throw new AssertionError(
          "LOAD_TOTAL_CLIENTS (" + totalClients + ") must be divisible by "
              + "LOAD_INSTANCE_COUNT (" + instanceCount + ").");
    }
    var waves = totalClients / instanceCount;
    var pathTemplate = resolveLoadPathTemplate(jmeterProps);
    var initPathTemplate = resolveLoadInitPathTemplate(jmeterProps, pathTemplate);

    return new LoadDriverSetupConfig(
        loadDriverBaseUrl,
        instanceCount,
        totalClients,
        waves,
        autoInit,
        waitReady,
        cleanupBeforeCreate,
        cleanupAfterTest,
        resetBetweenWaves,
        backgroundReset,
        Duration.ofSeconds(readyTimeoutSeconds),
        Duration.ofMillis(readyPollMs),
        Duration.ofSeconds(parsePositiveInt(
            jmeterProps.get("LOAD_INIT_STEP_TIMEOUT_S"), 30, "LOAD_INIT_STEP_TIMEOUT_S")),
        createBatchSize,
        waveDurationS,
        parsePositiveInt(jmeterProps.get("THREADS"), 1, "THREADS"),
        parsePositiveInt(jmeterProps.get("LOAD_PRECHECK_SAMPLE_SIZE"), 1, "LOAD_PRECHECK_SAMPLE_SIZE"),
        parseBoolean(jmeterProps.get("LOAD_PRECHECK_ENABLED"), true),
        parseBoolean(jmeterProps.get(LOAD_ONE_INSTANCE_PER_THREAD), false),
        parseBoolean(jmeterProps.get("LOAD_PERSIST_POPP_BINDINGS"), false),
        resolveLoadPrecheckMethod(jmeterProps),
        resolveLoadProxyPath(jmeterProps),
        pathTemplate,
        initPathTemplate,
        parseLoadInitFlow(jmeterProps.get("LOAD_INIT_FLOW")),
        trimToNull(jmeterProps.get(LOAD_SMCB_KEYSTORE_MANIFEST)),
        trimToNull(jmeterProps.get(LOAD_POPP_TOKEN_GENERATOR_URL)),
        trimToNull(jmeterProps.get("LOAD_FACHDIENST_URL")),
        trimToNull(jmeterProps.get(LOAD_INIT_BUFFER_TARGET_VAR)));
  }

  private String resolveLoadProxyPath(Map<String, String> jmeterProps) {
    var explicitPath = trimToNull(jmeterProps.get("LOAD_PROXY_PATH"));
    if (explicitPath != null) {
      return ensureStartsWithSlash(explicitPath);
    }
    return DEFAULT_GUARD_TOKEN_PATH;
  }

  private String resolveLoadPathTemplate(Map<String, String> jmeterProps) {
    var template = trimToNull(jmeterProps.get("LOAD_PATH_TEMPLATE"));
    if (template == null) {
      return DEFAULT_LOAD_PATH_TEMPLATE;
    }
    validateLoadPathTemplate(template, "LOAD_PATH_TEMPLATE");
    return template;
  }

  private String resolveLoadInitPathTemplate(
      Map<String, String> jmeterProps, String defaultPathTemplate) {
    var template = trimToNull(jmeterProps.get("LOAD_INIT_PATH_TEMPLATE"));
    if (template == null) {
      return defaultPathTemplate;
    }
    validateLoadPathTemplate(template, "LOAD_INIT_PATH_TEMPLATE");
    return template;
  }

  private void validateLoadPathTemplate(String template, String propertyName) {
    if (!template.contains("{id}")) {
      throw new AssertionError(
          propertyName + " must contain '{id}', e.g. /load/{id}{proxyPath}");
    }
    if (!template.contains("{proxyPath}")) {
      throw new AssertionError(
          propertyName + " must contain '{proxyPath}', e.g. /load/{id}{proxyPath}");
    }
  }

  private String resolveLoadPrecheckMethod(Map<String, String> jmeterProps) {
    var explicit = trimToNull(jmeterProps.get("LOAD_PRECHECK_METHOD"));
    if (explicit != null) {
      return explicit.toUpperCase(Locale.ROOT);
    }
    var httpMethod = trimToNull(jmeterProps.get("HTTP_METHOD"));
    return httpMethod == null ? "GET" : httpMethod.toUpperCase(Locale.ROOT);
  }

  private List<String> parseLoadInitFlow(String rawFlow) {
    var normalized = trimToNull(rawFlow);
    if (normalized == null) {
      return List.of();
    }
    return Stream.of(normalized.split(","))
        .map(JMeterPropertySupport::trimToNull)
        .filter(Objects::nonNull)
        .map(JMeterPropertySupport::ensureStartsWithSlash)
        .collect(Collectors.toList());
  }

  private void removeLoadDriverControlProperties(Map<String, String> jmeterProps) {
    Set<String> keys = new HashSet<>(jmeterProps.keySet());
    for (var key : keys) {
      if (key.startsWith("LOAD_") && !LOAD_PROPERTIES_REQUIRED_BY_PLAN.contains(key)) {
        jmeterProps.remove(key);
      }
    }
  }

  private void restorePoppBindingProperties(
      Map<String, String> jmeterProps,
      String smcbManifest,
      String poppTokenGeneratorUrl) {
    if (smcbManifest != null) {
      jmeterProps.put(LOAD_SMCB_KEYSTORE_MANIFEST, smcbManifest);
    }
    if (poppTokenGeneratorUrl != null) {
      jmeterProps.put(LOAD_POPP_TOKEN_GENERATOR_URL, poppTokenGeneratorUrl);
    }
  }

  private void removePoppBindingProperties(Map<String, String> jmeterProps) {
    jmeterProps.remove(LOAD_SMCB_KEYSTORE_MANIFEST);
    jmeterProps.remove(LOAD_POPP_TOKEN_GENERATOR_URL);
  }

  /**
   * Starts the background reset thread for a prepared load-driver context.
   */
  public Thread startBackgroundResetThread(
      LoadDriverContext context, java.util.concurrent.atomic.AtomicBoolean stopSignal) {
    if (context == null || context.backgroundResetIds() == null) {
      return null;
    }
    var resetIds = context.backgroundResetIds();
    var resetPathTemplate = context.backgroundResetPathTemplate();
    var resetStepTimeout = context.backgroundResetStepTimeout();
    var resetClient = context.client();
    var resetBaseUrl = context.baseUrl();
    return Thread.ofVirtual().name("background-reset").start(() -> {
      log.info("Background reset thread started: instances={}", resetIds.size());
      long totalResets = 0;
      while (!stopSignal.get()) {
        for (int instanceId : resetIds) {
          if (stopSignal.get()) {
            break;
          }
          var path = buildLoadInstancePath(instanceId, "/removeAuth", resetPathTemplate);
          var uri = URI.create(resetBaseUrl + path);
          try {
            var request = HttpRequest.newBuilder(uri).timeout(resetStepTimeout).GET().build();
            resetClient.send(request, HttpResponse.BodyHandlers.discarding());
            totalResets++;
          } catch (Exception e) {
            log.warn("Background reset failed for instanceId={}: {}", instanceId, e.getMessage());
          }
        }
        if (!stopSignal.get()) {
          log.info("Background reset cycle complete: totalResets={}", totalResets);
        }
      }
      log.info("Background reset thread stopped: totalResets={}", totalResets);
    });
  }
}
