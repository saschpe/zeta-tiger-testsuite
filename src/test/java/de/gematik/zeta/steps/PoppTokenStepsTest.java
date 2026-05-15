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

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import de.gematik.test.tiger.common.config.ConfigurationValuePrecedence;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link PoppTokenSteps}.
 */
class PoppTokenStepsTest {

  private HttpServer server;

  /**
   * Stops the embedded HTTP server and clears test configuration values.
   */
  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop(0);
    }
    clear("paths.popp.tokenGenerator");
    clear("testdata.popp.proofMethod");
    clear("testdata.popp.patientId");
    clear("testdata.popp.insurerId");
    clear("testdata.popp.actorProfessionOid");
    clear("POPP_TOKEN");
  }

  /**
   * Verifies that the step sends the supplied actor data to the token generator.
   *
   * @throws Exception on embedded server setup failure
   */
  @Test
  void fetchFreshPoppTokenUsesProvidedActorData() throws Exception {
    var tokenRequestBody = new AtomicReference<String>();

    server = HttpServer.create(new InetSocketAddress(0), 0);
    server.createContext("/token-generator", exchange -> {
      tokenRequestBody.set(readBody(exchange.getRequestBody()));
      writeResponse(exchange, "{\"tokenResults\":[\"GENERATED_POPP_TOKEN\"]}");
    });
    server.start();

    configure();
    var steps = new PoppTokenSteps();

    steps.fetchFreshPoppToken("1-20014060625", "1.2.276.0.76.4.50", "POPP_TOKEN");

    assertThat(read("POPP_TOKEN")).isEqualTo("GENERATED_POPP_TOKEN");
    assertThat(tokenRequestBody.get())
        .contains("\"actorId\":\"1-20014060625\"")
        .contains("\"actorProfessionOid\":\"1.2.276.0.76.4.50\"")
        .contains("\"patientId\":\"X110639491\"")
        .contains("\"insurerId\":\"109500969\"");
  }

  /**
   * Configures Tiger values used by the PoPP token step.
   */
  private void configure() {
    put("paths.popp.tokenGenerator", baseUrl() + "/token-generator");
    put("testdata.popp.proofMethod", "ehc-practitioner-user-x509");
    put("testdata.popp.patientId", "X110639491");
    put("testdata.popp.insurerId", "109500969");
    put("testdata.popp.actorProfessionOid", "1.2.276.0.76.4.32");
  }

  /**
   * Stores one Tiger test-context value.
   *
   * @param key configuration key
   * @param value configuration value
   */
  private void put(String key, String value) {
    TigerGlobalConfiguration.putValue(key, value, ConfigurationValuePrecedence.TEST_CONTEXT);
  }

  /**
   * Clears one Tiger test-context value.
   *
   * @param key configuration key
   */
  private void clear(String key) {
    TigerGlobalConfiguration.putValue(key, "", ConfigurationValuePrecedence.TEST_CONTEXT);
  }

  /**
   * Reads one Tiger configuration value.
   *
   * @param key configuration key
   * @return configuration value
   */
  private String read(String key) {
    return TigerGlobalConfiguration.readStringOptional(key)
        .orElseThrow(() -> new AssertionError("Missing Tiger variable: " + key));
  }

  /**
   * Returns the embedded server base URL.
   *
   * @return base URL
   */
  private String baseUrl() {
    return "http://localhost:" + server.getAddress().getPort();
  }

  /**
   * Writes one JSON response.
   *
   * @param exchange HTTP exchange
   * @param body response body
   * @throws IOException if writing fails
   */
  private void writeResponse(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
    var bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  /**
   * Reads a request body as UTF-8.
   *
   * @param inputStream request body stream
   * @return decoded request body
   * @throws IOException if reading fails
   */
  private String readBody(InputStream inputStream) throws IOException {
    return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
  }
}
