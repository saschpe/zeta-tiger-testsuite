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

package de.gematik.zeta.steps.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.test.tiger.common.config.ConfigurationValuePrecedence;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.zeta.steps.JwtSteps;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for JWT variant creation in {@link JwtSteps}.
 */
class JwtVariantStepsTest {

  private static final String TARGET_VARIABLE = "MALFORMED_DPOP_JWT";
  private static final String PRIVATE_KEY_RESOURCE = "keys/popp-token-server_ecKey.pem";

  /**
   * Clears Tiger variables written by the tested Cucumber step.
   */
  @AfterEach
  void tearDown() {
    TigerGlobalConfiguration.putValue(TARGET_VARIABLE, "",
        ConfigurationValuePrecedence.TEST_CONTEXT);
  }

  /**
   * Verifies that the unquoted-key variant stays compact while making the JOSE header malformed.
   */
  @Test
  void buildUnquotedHeaderKeyVariantCreatesCompactJwtWithMalformedHeaderJson() {
    var originalDpopJwt = compactJwt(
        """
            {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"abc","y":"def"}}\
            """,
        """
            {"jti":"test","htm":"POST","htu":"https://server.example/token","iat":1700000000}\
            """);
    var steps = new JwtSteps();

    steps.buildJwtVariant(
        "invalid_header_json_unquoted_keys",
        originalDpopJwt,
        loadResource(PRIVATE_KEY_RESOURCE),
        TARGET_VARIABLE);

    var malformedDpopJwt = readTigerValue(TARGET_VARIABLE);
    var parts = malformedDpopJwt.split("\\.", -1);

    assertThat(parts).hasSize(3);
    var rawHeader = decodeBase64Url(parts[0]);

    assertThat(rawHeader)
        .contains("typ:\"dpop+jwt\"")
        .contains("jwk:{kty:\"EC\"");
    assertThrows(JsonProcessingException.class, () -> new ObjectMapper().readTree(rawHeader));
  }

  /**
   * Verifies that the unquoted-key variant keeps the JOSE header valid while making the payload
   * malformed.
   */
  @Test
  void buildUnquotedPayloadKeyVariantCreatesCompactJwtWithMalformedPayloadJson() {
    var originalDpopJwt = compactJwt(
        """
            {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"abc","y":"def"}}\
            """,
        """
            {"jti":"test","htm":"POST","htu":"https://server.example/token","iat":1700000000}\
            """);
    var steps = new JwtSteps();

    steps.buildJwtVariant(
        "invalid_payload_json_unquoted_keys",
        originalDpopJwt,
        loadResource(PRIVATE_KEY_RESOURCE),
        TARGET_VARIABLE);

    var malformedDpopJwt = readTigerValue(TARGET_VARIABLE);
    var parts = malformedDpopJwt.split("\\.", -1);

    assertThat(parts).hasSize(3);
    var rawHeader = decodeBase64Url(parts[0]);
    var rawPayload = decodeBase64Url(parts[1]);

    assertThat(rawHeader).contains("\"typ\":\"dpop+jwt\"");
    assertThat(rawPayload)
        .contains("jti:\"test\"")
        .contains("htu:\"https://server.example/token\"");
    assertThrows(JsonProcessingException.class, () -> new ObjectMapper().readTree(rawPayload));
  }

  /**
   * Creates a compact JWT string from raw header and payload text with a placeholder signature.
   *
   * @param rawHeader raw JOSE header JSON
   * @param rawPayload raw JWT payload JSON
   * @return compact JWT used as a variant template
   */
  private String compactJwt(String rawHeader, String rawPayload) {
    return encodeBase64Url(rawHeader.trim())
        + "."
        + encodeBase64Url(rawPayload.trim())
        + ".placeholder";
  }

  /**
   * Encodes a string with Base64URL without padding.
   *
   * @param value raw string value
   * @return Base64URL encoded value
   */
  private String encodeBase64Url(String value) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Decodes a Base64URL string as UTF-8 text.
   *
   * @param value Base64URL encoded value
   * @return decoded UTF-8 text
   */
  private String decodeBase64Url(String value) {
    return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
  }

  /**
   * Reads a classpath resource as UTF-8 text.
   *
   * @param resourcePath classpath resource path
   * @return resource contents
   */
  private String loadResource(String resourcePath) {
    try (InputStream in = JwtVariantStepsTest.class.getClassLoader()
        .getResourceAsStream(resourcePath)) {
      if (in == null) {
        throw new IllegalArgumentException("Resource not found: " + resourcePath);
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to read resource: " + resourcePath, e);
    }
  }

  /**
   * Reads a Tiger configuration value from the test context.
   *
   * @param key Tiger configuration key
   * @return stored value
   */
  private String readTigerValue(String key) {
    return TigerGlobalConfiguration.readStringOptional(key)
        .orElseThrow(() -> new AssertionError("Missing Tiger variable: " + key));
  }
}
