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

import static de.gematik.zeta.services.JMeterPropertySupport.escapeJson;
import static de.gematik.zeta.services.JMeterPropertySupport.sanitizeLogBody;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.zeta.services.model.SmcbAdmissionData;
import de.gematik.zeta.services.model.SmcbManifestEntry;
import de.gematik.zeta.services.model.SmcbPoppClaims;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.security.auth.x500.X500Principal;
import lombok.extern.slf4j.Slf4j;

/**
 * Extracts SMC-B claims and requests PoPP tokens.
 */
@Slf4j
public class PoppTokenService {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String GEMATIK_PROFESSIONAL_INFO_EXTENSION_OID = "1.3.36.8.3.3";
  private static final int POPP_BATCH_SIZE = 1000;
  private static final int POPP_PARALLEL_BATCHES = 8;

  /**
   * Extracts actor identifiers from SMC-B manifest entries in manifest order.
   */
  public List<SmcbPoppClaims> extractPoppClaims(List<SmcbManifestEntry> entries) throws Exception {
    var n = entries.size();
    var parallelism = Math.min(32, Runtime.getRuntime().availableProcessors() * 4);
    var executor = Executors.newFixedThreadPool(parallelism);
    @SuppressWarnings("unchecked")
    Future<SmcbPoppClaims>[] futures = new Future[n];
    var t0 = System.nanoTime();
    for (var i = 0; i < n; i++) {
      final var entry = entries.get(i);
      futures[i] = executor.submit(() -> extractPoppClaimsFromKeystore(entry));
    }
    try {
      var claims = new ArrayList<SmcbPoppClaims>(n);
      for (var i = 0; i < n; i++) {
        claims.add(futures[i].get());
        if (i > 0 && i % 5000 == 0) {
          log.info("Extracted PoPP claims for {}/{} certificates in {}ms",
              i, n, Duration.ofNanos(System.nanoTime() - t0).toMillis());
        }
      }
      log.info("Extracted PoPP claims for {} certificates in {}ms",
          n, Duration.ofNanos(System.nanoTime() - t0).toMillis());
      return claims;
    } catch (java.util.concurrent.ExecutionException e) {
      throw new IOException("Failed to extract PoPP claims in parallel", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while extracting PoPP claims in parallel", e);
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * Requests one PoPP token per SMC-B claim from the configured token generator.
   */
  public List<String> fetchPoppTokensBatch(
      HttpClient client, String tokenGeneratorUrl, List<SmcbPoppClaims> poppClaims)
      throws Exception {
    var totalBatches = (int) Math.ceil((double) poppClaims.size() / POPP_BATCH_SIZE);
    log.info("Fetching {} PoPP tokens in {} batches with parallelism {}",
        poppClaims.size(), totalBatches, POPP_PARALLEL_BATCHES);

    var batches = new ArrayList<List<SmcbPoppClaims>>(totalBatches);
    for (var offset = 0; offset < poppClaims.size(); offset += POPP_BATCH_SIZE) {
      batches.add(poppClaims.subList(offset, Math.min(offset + POPP_BATCH_SIZE, poppClaims.size())));
    }

    var executor = Executors.newFixedThreadPool(POPP_PARALLEL_BATCHES);
    @SuppressWarnings("unchecked")
    Future<List<String>>[] futures = new Future[totalBatches];
    var t0 = System.nanoTime();
    for (var i = 0; i < totalBatches; i++) {
      final var batchNum = i + 1;
      final var batch = batches.get(i);
      futures[i] = executor.submit(() -> {
        log.info("PoPP token batch {}/{} starting, size={}", batchNum, totalBatches, batch.size());
        var tokens = fetchPoppTokensSingleBatch(client, tokenGeneratorUrl, batch);
        log.info("PoPP token batch {}/{} done in {}ms total elapsed",
            batchNum, totalBatches, Duration.ofNanos(System.nanoTime() - t0).toMillis());
        return tokens;
      });
    }
    try {
      var allTokens = new ArrayList<String>(poppClaims.size());
      for (var i = 0; i < totalBatches; i++) {
        allTokens.addAll(futures[i].get());
      }
      log.info("Fetched {} PoPP token batches in {}ms, total tokens={}",
          totalBatches, Duration.ofNanos(System.nanoTime() - t0).toMillis(), allTokens.size());
      if (allTokens.size() != poppClaims.size()) {
        throw new AssertionError("PoPP token generator returned " + allTokens.size()
            + " tokens for " + poppClaims.size() + " actorIds across all batches");
      }
      return allTokens;
    } catch (java.util.concurrent.ExecutionException e) {
      throw new IOException("PoPP token batch failed", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while waiting for PoPP token batch", e);
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * Extracts one string claim from the payload section of a compact JWT.
   */
  public String extractJwtStringClaim(String jwt, String claimName) {
    if (jwt == null || jwt.isBlank()) {
      return null;
    }

    var parts = jwt.split("\\.", 3);
    if (parts.length < 2) {
      return null;
    }

    try {
      var payload = new String(
          Base64.getUrlDecoder().decode(parts[1]),
          StandardCharsets.UTF_8);
      return JSON.readTree(payload).path(claimName).asText(null);
    } catch (Exception e) {
      log.warn("Could not decode JWT claim '{}' for PoPP binding log: {}", claimName, e.getMessage());
      return null;
    }
  }

  private SmcbPoppClaims extractPoppClaimsFromKeystore(SmcbManifestEntry entry) throws Exception {
    var keystoreBytes = Base64.getDecoder().decode(entry.keystoreB64());
    var ks = KeyStore.getInstance("PKCS12");
    ks.load(new ByteArrayInputStream(keystoreBytes), entry.keystorePassword().toCharArray());

    var alias = entry.keystoreAlias();
    var cert = ks.getCertificate(alias);
    if (cert == null) {
      throw new AssertionError(
          "No certificate found in keystore '" + entry.stem() + "' for alias '" + alias + "'");
    }
    var x509Certificate = (X509Certificate) cert;
    var admissionData = extractAdmissionDataFromGematikExtension(x509Certificate);
    if (admissionData != null && admissionData.actorId() != null) {
      return new SmcbPoppClaims(
          admissionData.actorId(),
          admissionData.professionOid() == null || admissionData.professionOid().isBlank()
              ? "1.2.276.0.76.4.32"
              : admissionData.professionOid());
    }

    var subject = x509Certificate.getSubjectX500Principal();
    var dn = subject.getName(X500Principal.RFC2253);
    var street = extractDnAttribute(dn, "STREET", entry.stem());
    return new SmcbPoppClaims("5-2-KH-" + street, "1.2.276.0.76.4.32");
  }

  private SmcbAdmissionData extractAdmissionDataFromGematikExtension(X509Certificate certificate) {
    var extensionValue = certificate.getExtensionValue(GEMATIK_PROFESSIONAL_INFO_EXTENSION_OID);
    if (extensionValue == null || extensionValue.length == 0) {
      return null;
    }

    try {
      var inner = unwrapDerOctetString(extensionValue);
      return new SmcbAdmissionData(
          findActorIdInDer(inner, 0, inner.length),
          findProfessionOidInDer(inner, 0, inner.length));
    } catch (Exception e) {
      log.warn(
          "Could not parse gematik admission extension {}: {}",
          GEMATIK_PROFESSIONAL_INFO_EXTENSION_OID,
          e.getMessage());
      return null;
    }
  }

  private String findActorIdInDer(byte[] der, int start, int end) {
    var offset = start;
    while (offset < end) {
      var tag = der[offset] & 0xFF;
      var lengthInfoOffset = offset + 1;
      var length = readDerLength(der, lengthInfoOffset);
      var lengthFieldSize = derLengthFieldSize(der, lengthInfoOffset);
      var valueOffset = lengthInfoOffset + lengthFieldSize;
      var valueEnd = valueOffset + length;
      if (valueEnd > end) {
        throw new IllegalArgumentException("DER value exceeds parent structure");
      }

      if (isDerStringTag(tag)) {
        var value = new String(der, valueOffset, length, StandardCharsets.UTF_8);
        if (value.startsWith("5-2-")) {
          return value;
        }
      }

      if (shouldDescendIntoDerValue(tag, der, valueOffset, valueEnd)) {
        var nested = findActorIdInDer(der, valueOffset, valueEnd);
        if (nested != null) {
          return nested;
        }
      }

      offset = valueEnd;
    }
    return null;
  }

  private String findProfessionOidInDer(byte[] der, int start, int end) {
    var offset = start;
    while (offset < end) {
      var tag = der[offset] & 0xFF;
      var lengthInfoOffset = offset + 1;
      var length = readDerLength(der, lengthInfoOffset);
      var lengthFieldSize = derLengthFieldSize(der, lengthInfoOffset);
      var valueOffset = lengthInfoOffset + lengthFieldSize;
      var valueEnd = valueOffset + length;
      if (valueEnd > end) {
        throw new IllegalArgumentException("DER value exceeds parent structure");
      }

      if (isDerStringTag(tag)) {
        var value = new String(der, valueOffset, length, StandardCharsets.UTF_8);
        if (value.matches("1\\.2\\.276\\.0\\.76\\.4\\.\\d+")) {
          return value;
        }
      }

      if (shouldDescendIntoDerValue(tag, der, valueOffset, valueEnd)) {
        var nested = findProfessionOidInDer(der, valueOffset, valueEnd);
        if (nested != null) {
          return nested;
        }
      }

      offset = valueEnd;
    }
    return null;
  }

  private byte[] unwrapDerOctetString(byte[] encodedValue) {
    if (encodedValue.length < 2 || (encodedValue[0] & 0xFF) != 0x04) {
      throw new IllegalArgumentException("Expected DER OCTET STRING");
    }
    var length = readDerLength(encodedValue, 1);
    var valueOffset = 1 + derLengthFieldSize(encodedValue, 1);
    var valueEnd = valueOffset + length;
    if (valueEnd > encodedValue.length) {
      throw new IllegalArgumentException("Invalid DER OCTET STRING length");
    }
    return Arrays.copyOfRange(encodedValue, valueOffset, valueEnd);
  }

  private int readDerLength(byte[] der, int offset) {
    if (offset >= der.length) {
      throw new IllegalArgumentException("DER offset exceeds array bounds");
    }
    var first = der[offset] & 0xFF;
    if ((first & 0x80) == 0) {
      return first;
    }

    var byteCount = first & 0x7F;
    if (byteCount == 0 || byteCount > 4) {
      throw new IllegalArgumentException("Unsupported DER length encoding");
    }
    var length = 0;
    for (var i = 0; i < byteCount; i++) {
      if (offset + 1 + i >= der.length) {
        throw new IllegalArgumentException("DER length field exceeds array bounds");
      }
      length = (length << 8) | (der[offset + 1 + i] & 0xFF);
    }
    return length;
  }

  private int derLengthFieldSize(byte[] der, int offset) {
    var first = der[offset] & 0xFF;
    return (first & 0x80) == 0 ? 1 : 1 + (first & 0x7F);
  }

  private boolean isDerStringTag(int tag) {
    return tag == 0x0C || tag == 0x13 || tag == 0x16;
  }

  private boolean shouldDescendIntoDerValue(int tag, byte[] der, int valueOffset, int valueEnd) {
    if (valueOffset >= valueEnd) {
      return false;
    }
    if ((tag & 0x20) != 0) {
      return true;
    }
    var firstNestedTag = der[valueOffset] & 0xFF;
    return firstNestedTag == 0x30 || firstNestedTag == 0x31 || firstNestedTag == 0xA0;
  }

  private String extractDnAttribute(String dn, String attributeName, String stem) {
    for (var part : dn.split("(?<!\\\\),")) {
      var trimmed = part.trim();
      var eq = trimmed.indexOf('=');
      if (eq < 0) {
        continue;
      }
      var key = trimmed.substring(0, eq).trim();
      if (attributeName.equalsIgnoreCase(key)) {
        var value = trimmed.substring(eq + 1).trim();
        if (value.startsWith("\"") && value.endsWith("\"")) {
          value = value.substring(1, value.length() - 1);
        }
        return value.replace("\\,", ",").replace("\\+", "+").replace("\\\"", "\"")
            .replace("\\\\", "\\").replace("\\<", "<").replace("\\>", ">")
            .replace("\\;", ";").replace("\\=", "=").replace("\\#", "#");
      }
    }
    throw new AssertionError(
        "Certificate in keystore '" + stem + "' is missing STREET attribute in Subject DN: " + dn);
  }

  private List<String> fetchPoppTokensSingleBatch(
      HttpClient client, String tokenGeneratorUrl, List<SmcbPoppClaims> poppClaims)
      throws Exception {
    var sb = new StringBuilder("{\"tokenParamsList\":[");
    for (var i = 0; i < poppClaims.size(); i++) {
      if (i > 0) {
        sb.append(',');
      }
      var claims = poppClaims.get(i);
      sb.append("{\"proofMethod\":\"ehc-practitioner-user-x509\"")
          .append(",\"patientId\":\"X110639491\"")
          .append(",\"insurerId\":\"109500969\"")
          .append(",\"actorId\":\"").append(escapeJson(claims.actorId())).append("\"")
          .append(",\"actorProfessionOid\":\"")
          .append(escapeJson(claims.actorProfessionOid())).append("\"")
          .append("}");
    }
    sb.append("]}");

    var body = sb.toString();
    HttpResponse<String> response = null;
    IOException lastException = null;
    for (var attempt = 1; attempt <= 3; attempt++) {
      var request = HttpRequest.newBuilder(URI.create(tokenGeneratorUrl))
          .timeout(Duration.ofSeconds(60))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();
      try {
        response = client.send(request, HttpResponse.BodyHandlers.ofString());
        lastException = null;
        break;
      } catch (IOException e) {
        lastException = e;
        log.warn("PoPP token batch attempt {}/3 failed ({}), retrying", attempt, e.getMessage());
      }
    }
    if (lastException != null) {
      throw lastException;
    }
    if (response.statusCode() != 200) {
      throw new AssertionError(
          "PoPP token generator returned HTTP " + response.statusCode()
              + " for " + poppClaims.size() + " actorIds: " + sanitizeLogBody(response.body()));
    }
    var node = JSON.readTree(response.body());
    var results = node.path("tokenResults");
    if (!results.isArray() || results.size() != poppClaims.size()) {
      throw new AssertionError(
          "PoPP token generator returned " + results.size() + " tokens for "
              + poppClaims.size() + " actorIds: " + sanitizeLogBody(response.body()));
    }
    List<String> tokens = new ArrayList<>(poppClaims.size());
    for (var token : results) {
      tokens.add(token.asText());
    }
    return tokens;
  }
}
