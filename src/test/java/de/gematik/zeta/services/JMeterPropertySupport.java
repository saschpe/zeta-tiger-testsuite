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

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import java.util.Map;

/**
 * Shared parsing and formatting helpers for JMeter/load-driver properties.
 */
public final class JMeterPropertySupport {

  public static final String DEFAULT_GUARD_TOKEN_PATH =
      "/auth/realms/zeta-guard/protocol/openid-connect/token";
  public static final String DEFAULT_LOAD_PATH_TEMPLATE = "/load/{id}{proxyPath}";
  public static final String LOAD_CREATE_BODY_INLINE = "LOAD_CREATE_BODY_INLINE";
  public static final String LOAD_ONE_INSTANCE_PER_THREAD = "LOAD_ONE_INSTANCE_PER_THREAD";
  public static final String LOAD_SMCB_KEYSTORE_MANIFEST = "LOAD_SMCB_KEYSTORE_MANIFEST";
  public static final String LOAD_SMCB_KEYSTORE_POOL_DIR = "LOAD_SMCB_KEYSTORE_POOL_DIR";
  public static final String LOAD_SMCB_KEYSTORE_PASSWORD = "LOAD_SMCB_KEYSTORE_PASSWORD";
  public static final String LOAD_POPP_TOKEN_GENERATOR_URL = "LOAD_POPP_TOKEN_GENERATOR_URL";
  public static final String LOAD_INIT_BUFFER_TARGET_VAR = "LOAD_INIT_BUFFER_TARGET_VAR";

  private JMeterPropertySupport() {
  }

  /**
   * Returns a required property value.
   *
   * @param properties property map
   * @param key        property key
   * @return normalized property value
   */
  public static String requireProperty(Map<String, String> properties, String key) {
    var value = trimToNull(properties.get(key));
    if (value == null) {
      throw new AssertionError(key + " is required but missing.");
    }
    return value;
  }

  /**
   * Parses a positive integer property.
   */
  public static int parsePositiveInt(String value, int fallback, String propertyName) {
    var normalized = trimToNull(value);
    if (normalized == null) {
      return fallback;
    }
    try {
      var parsed = Integer.parseInt(normalized);
      if (parsed < 1) {
        throw new AssertionError(propertyName + " must be >= 1 but was " + normalized);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new AssertionError(propertyName + " must be integer but was " + normalized);
    }
  }

  /**
   * Parses a boolean property.
   */
  public static boolean parseBoolean(String value, boolean fallback) {
    var normalized = trimToNull(value);
    return normalized == null ? fallback : Boolean.parseBoolean(normalized);
  }

  /**
   * Converts blank strings to {@code null}.
   */
  public static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    var trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  /**
   * Ensures one path starts with a slash.
   */
  public static String ensureStartsWithSlash(String value) {
    var trimmed = trimToNull(value);
    if (trimmed == null) {
      return "/";
    }
    return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
  }

  /**
   * Normalizes a base URL by removing the trailing slash.
   */
  public static String normalizeBaseUrl(String baseUrl) {
    var trimmed = trimToNull(baseUrl);
    if (trimmed == null) {
      throw new AssertionError("LOAD_DRIVER_BASE_URL is required but missing");
    }
    return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
  }

  /**
   * Builds a load-driver instance path from a template.
   */
  public static String buildLoadInstancePath(int instanceId, String proxyPath, String pathTemplate) {
    var path = pathTemplate
        .replace("{id}", Integer.toString(instanceId))
        .replace("{proxyPath}", ensureStartsWithSlash(proxyPath));
    return path.startsWith("/") ? path : "/" + path;
  }

  /**
   * Escapes one value for hand-built JSON snippets.
   */
  public static String escapeJson(String value) {
    var out = new StringBuilder(value.length() + 16);
    for (var i = 0; i < value.length(); i++) {
      var c = value.charAt(i);
      switch (c) {
        case '\\' -> out.append("\\\\");
        case '"' -> out.append("\\\"");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> out.append(c);
      }
    }
    return out.toString();
  }

  /**
   * Compacts and truncates a response body for logs and assertion messages.
   */
  public static String sanitizeLogBody(String body) {
    if (body == null) {
      return "";
    }
    var compact = body.replace("\n", " ").replace("\r", " ");
    return compact.length() > 1000 ? compact.substring(0, 1000) + "..." : compact;
  }

  /**
   * Resolves Tiger placeholders when possible and otherwise keeps the original value.
   */
  public static String resolveTigerPlaceholders(String value) {
    if (value == null || !value.contains("${")) {
      return value;
    }
    try {
      return TigerGlobalConfiguration.resolvePlaceholders(value);
    } catch (Exception e) {
      return value;
    }
  }
}
