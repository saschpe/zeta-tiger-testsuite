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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.gematik.test.tiger.common.config.ConfigurationValuePrecedence;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import io.cucumber.java.de.Und;
import io.cucumber.java.en.And;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Cucumber step definitions for JWT (JSON Web Token) manipulation and variant generation.
 */
@Slf4j
public class JwtSteps {

  private final SignatureVerificationSteps signatureVerificationSteps =
      new SignatureVerificationSteps();

  /**
   * Signs the provided JWT claim set with RS256 and returns the compact serialized token.
   *
   * @param privateKey RSA private key used for signing
   * @param claimSet   JSON string representation of the claims
   * @return serialized JWT string
   */
  public static String signJwtWithRs256(RSAPrivateKey privateKey, String claimSet) {
    // Header with RS256 algorithm
    JWSHeader header = new Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
    // Try to parse provided claims
    JWTClaimsSet claimsSet;
    try {
      claimsSet = JWTClaimsSet.parse(claimSet);
    } catch (ParseException e) {
      throw new AssertionError("Parsing of the provided claims failed for " + claimSet);
    }
    // Create signed JWT instance
    SignedJWT signedJwt = new SignedJWT(header, claimsSet);
    // Initialize signer with private RSA key
    RSASSASigner signer = new RSASSASigner(privateKey);
    // Sign token
    try {
      signedJwt.sign(signer);
    } catch (JOSEException e) {
      throw new AssertionError("Signing operation failed with " + e.getClass().getSimpleName());
    }
    // Serialize and return JWT
    return signedJwt.serialize();
  }

  /**
   * Loads an RSA private key from the classpath.
   *
   * @param filename classpath resource pointing to the PEM encoded key
   * @return parsed RSA private key
   */
  public static RSAPrivateKey loadPrivateKey(String filename) {
    String cp = filename.trim();
    final String resource = cp.startsWith("/") ? cp.substring(1) : cp;
    String alg = null;
    try (InputStream in = JwtSteps.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IllegalArgumentException(
            "Keyfile not found in the path under resources: " + resource);
      }
      String keyPem = new String(in.readAllBytes(), StandardCharsets.UTF_8);

      // Remove PEM header and footer markers
      keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s", "");
      // Decode Base64 encoded payload
      byte[] encoded = Base64.getDecoder().decode(keyPem);
      // Build PKCS8 key specification
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
      // Create RSA key from spec
      alg = "RSA";
      KeyFactory kf = KeyFactory.getInstance(alg);
      return (RSAPrivateKey) kf.generatePrivate(keySpec);
    } catch (IOException | InvalidKeySpecException e) {
      throw new AssertionError("Reading failed for file " + filename);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError("Did not find " + alg + " algorithm in KeyFactory.");
    }
  }



  /**
   * Builds a predefined compact JWT/JWS test variant from an existing valid token and stores it in
   * the Tiger configuration for later reuse in feature steps.
   *
   * <p>The variants are intentionally focused on RFC 7519 / RFC 7515 negative parsing and
   * validation paths for Guard integration tests. Variants that need a still-valid outer signature
   * are re-signed with the provided EC private key, while pure malformed compact-serialization
   * cases are emitted without re-signing.</p>
   *
   * @param variant       symbolic variant name describing the malformed JWT/JWS case
   * @param token         original valid compact JWT that serves as the template
   * @param privateKeyPem PEM encoded EC private key used for variants that require re-signing
   * @param varName       Tiger configuration variable receiving the generated compact token
   */
  @Und("erzeuge die JWT-Variante {tigerResolvedString} aus {tigerResolvedString} mit privatem Schlüssel {tigerResolvedString} und speichere in Variable {tigerResolvedString}")
  @And("build JWT variant {tigerResolvedString} from {tigerResolvedString} using private key {tigerResolvedString} and store in variable {tigerResolvedString}")
  public void buildJwtVariant(String variant, String token, String privateKeyPem, String varName) {
    var result = buildJwtVariantInternal(variant, token, privateKeyPem);
    TigerGlobalConfiguration.putValue(varName, result,
        ConfigurationValuePrecedence.TEST_CONTEXT);
    log.info("Storing JWT variant '{}' in variable '{}'", variant, varName);
  }

  /**
   * Verifies that a generated JWT variant has the expected local signature integrity before it is
   * sent to the Guard.
   *
   * <p>This prevents false positives where a failed re-signature would accidentally still lead to
   * the expected remote error response. Variants that are supposed to keep a valid outer signature
   * are verified locally, while the dedicated {@code invalid_signature} variant must fail local
   * signature verification. Pure parsing-malformation variants are intentionally ignored here.</p>
   *
   * @param variant generated JWT variant name
   * @param jwt     generated compact JWT/JWS variant
   */
  @Und("prüfe die JWT-Variante {tigerResolvedString} in {tigerResolvedString} hat lokal die erwartete Signaturintegrität")
  @And("check JWT variant {tigerResolvedString} in {tigerResolvedString} has the expected local signature integrity")
  public void verifyJwtVariantHasExpectedLocalSignatureIntegrity(String variant, String jwt) {
    var normalizedVariant = variant.trim().toLowerCase();
    switch (normalizedVariant) {
      case "unknown_header_parameter", "unsupported_crit", "unsupported_alg", "missing_alg",
          "duplicate_alg_headers", "nested_cty_jwt_valid_inner",
          "nested_cty_jwt_invalid_inner" -> assertThat(
          signatureVerificationSteps.hasCryptographicallyValidEmbeddedEs256Signature(jwt))
          .as("JWT variant '%s' must keep a locally valid cryptographic signature", variant)
          .isTrue();
      case "invalid_signature" -> assertThat(
          signatureVerificationSteps.hasCryptographicallyValidEmbeddedEs256Signature(jwt))
          .as("JWT variant '%s' must be locally cryptographically invalid", variant)
          .isFalse();
      default -> log.debug("Skipping local signature integrity check for JWT variant '{}'", variant);
    }
  }

  /**
   * Builds a DPoP proof variant where one mandatory top-level payload claim is removed and stores
   * the compact serialized result in a test variable.
   *
   * @param token original valid DPoP JWT
   * @param claimName top-level payload claim to remove, for example {@code jti} or {@code ath}
   * @param privateKeyPem EC private key used to re-sign the manipulated proof
   * @param varName Tiger configuration variable receiving the manipulated compact token
   */
  @Und("erzeuge aus {tigerResolvedString} ein DPoP JWT ohne Claim {string} mit privatem Schlüssel {tigerResolvedString} und speichere in Variable {tigerResolvedString}")
  @And("build DPoP JWT from {tigerResolvedString} without claim {string} using private key {tigerResolvedString} and store in variable {tigerResolvedString}")
  public void buildDpopJwtWithoutClaim(
      String token, String claimName, String privateKeyPem, String varName) {
    var result = buildDpopJwtWithoutClaimInternal(token, claimName, privateKeyPem);
    TigerGlobalConfiguration.putValue(varName, result,
        ConfigurationValuePrecedence.TEST_CONTEXT);
    log.info("Storing DPoP JWT without claim '{}' in variable '{}'", claimName, varName);
  }

  /**
   * Builds an unsecured DPoP proof using {@code alg=none} and stores the compact serialized
   * result in a test variable.
   *
   * @param token original valid DPoP JWT
   * @param varName Tiger configuration variable receiving the manipulated compact token
   */
  @Und("erzeuge aus {tigerResolvedString} ein DPoP JWT mit Header-Algorithmus none und speichere in Variable {tigerResolvedString}")
  @And("build DPoP JWT from {tigerResolvedString} with header algorithm none and store in variable {tigerResolvedString}")
  public void buildDpopJwtWithHeaderAlgNone(String token, String varName) {
    var result = buildDpopJwtWithHeaderAlgNoneInternal(token);
    TigerGlobalConfiguration.putValue(varName, result,
        ConfigurationValuePrecedence.TEST_CONTEXT);
    log.info("Storing unsecured DPoP JWT with alg=none in variable '{}'", varName);
  }

  /**
   * Creates one of the supported compact JWT/JWS variants from an original valid token.
   *
   * @param variant       symbolic variant selector
   * @param token         original valid compact JWT
   * @param privateKeyPem PEM encoded EC private key used when a variant needs a fresh signature
   * @return generated compact token variant
   */
  private String buildJwtVariantInternal(String variant, String token, String privateKeyPem) {
    var parts = token.split("\\.", -1);
    if (parts.length != 3) {
      throw new AssertionError("Original JWT must be compact JWS with exactly 3 segments.");
    }

    var rawHeaderJson = decodeBase64UrlSegment(parts[0], "header");
    var rawPayload = decodeBase64UrlSegment(parts[1], "payload");
    var normalizedVariant = variant.trim().toLowerCase();

    return switch (normalizedVariant) {
      case "two_segments" -> parts[0] + "." + parts[1];
      case "invalid_header_base64url" -> "###." + parts[1] + "." + parts[2];
      case "invalid_payload_base64url" -> parts[0] + ".###." + parts[2];
      case "invalid_signature_base64url" -> parts[0] + "." + parts[1] + ".###";
      case "invalid_header_json" -> encodeBase64Url("{") + "." + parts[1] + "." + parts[2];
      case "invalid_header_json_unquoted_keys" -> signEs256CompactJwt(
          removeJsonFieldNameQuotes(rawHeaderJson),
          rawPayload,
          privateKeyPem);
      case "invalid_payload_json" -> parts[0] + "." + encodeBase64Url("{") + "." + parts[2];
      case "invalid_payload_json_unquoted_keys" -> signEs256CompactJwt(
          rawHeaderJson,
          removeJsonFieldNameQuotes(rawPayload),
          privateKeyPem);
      case "unknown_header_parameter" -> signEs256CompactJwt(
          addUnknownHeaderParameter(rawHeaderJson),
          rawPayload,
          privateKeyPem);
      case "unsupported_crit" -> signEs256CompactJwt(
          addUnsupportedCritHeader(rawHeaderJson),
          rawPayload,
          privateKeyPem);
      case "unsupported_alg" -> signEs256CompactJwt(
          replaceTopLevelHeaderParameter(rawHeaderJson, "alg", "RS999"),
          rawPayload,
          privateKeyPem);
      case "missing_alg" -> signEs256CompactJwt(
          removeTopLevelHeaderParameter(rawHeaderJson, "alg"),
          rawPayload,
          privateKeyPem);
      case "duplicate_alg_headers" -> signEs256CompactJwt(
          duplicateAlgHeader(rawHeaderJson),
          rawPayload,
          privateKeyPem);
      case "invalid_signature" -> createInvalidSignatureVariant(rawHeaderJson, rawPayload, parts[2]);
      case "jwe_like_five_segments" -> parts[0]
          + ".ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.dGFn";
      case "nested_cty_jwt_valid_inner" -> createNestedJwtVariantWithValidInner(
          token,
          rawHeaderJson,
          privateKeyPem);
      case "nested_cty_jwt_invalid_inner" -> signEs256CompactJwt(
          addNestedJwtContentType(rawHeaderJson),
          "###.eyJpc3MiOiJ6ZXRhLXRlc3QifQ.signature",
          privateKeyPem);
      default -> throw new AssertionError("Unknown JWT variant " + variant);
    };
  }

  /**
   * Builds a compact DPoP JWT variant with one removed top-level payload claim.
   *
   * @param token original valid DPoP proof
   * @param claimName top-level payload claim to remove
   * @param privateKeyPem EC private key used to re-sign the manipulated proof
   * @return compact ES256 DPoP proof without the requested claim
   */
  private String buildDpopJwtWithoutClaimInternal(
      String token, String claimName, String privateKeyPem) {
    var parts = requireCompactJwtParts(token, "Original DPoP JWT");
    var rawHeaderJson = decodeBase64UrlSegment(parts[0], "DPoP header");
    var rawPayloadJson = decodeBase64UrlSegment(parts[1], "DPoP payload");
    var payload = parseJsonObject(rawPayloadJson, "DPoP payload");
    var removedClaim = payload.remove(claimName);

    assertThat(removedClaim)
        .as("Original DPoP payload must contain claim '%s'", claimName)
        .isNotNull();

    return signEs256CompactJwt(rawHeaderJson, payload.toString(), privateKeyPem);
  }

  /**
   * Builds an unsecured compact DPoP JWT with {@code alg=none}.
   *
   * @param token original valid DPoP proof
   * @return compact unsecured JWT with empty signature part
   */
  private String buildDpopJwtWithHeaderAlgNoneInternal(String token) {
    var parts = requireCompactJwtParts(token, "Original DPoP JWT");
    var header = parseJsonObject(decodeBase64UrlSegment(parts[0], "DPoP header"), "DPoP header");
    header.put("alg", "none");
    return encodeBase64Url(header.toString()) + "." + parts[1] + ".";
  }

  /**
   * Splits a compact JWT and validates that it contains exactly three segments.
   *
   * @param token compact JWT string
   * @param description human-readable token description for assertion messages
   * @return the three compact JWT segments
   */
  private String[] requireCompactJwtParts(String token, String description) {
    var parts = token.split("\\.", -1);
    assertThat(parts)
        .as("%s must be compact serialized with exactly 3 segments", description)
        .hasSize(3);
    return parts;
  }

  /**
   * Decodes one Base64URL JWT segment into its raw UTF-8 text representation.
   *
   * @param segment     compact JWT segment
   * @param description human-readable segment name for error messages
   * @return decoded raw UTF-8 text
   */
  private String decodeBase64UrlSegment(String segment, String description) {
    try {
      return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      throw new AssertionError("Failed to decode JWT " + description + " segment.", e);
    }
  }

  /**
   * Encodes raw UTF-8 text as Base64URL without padding.
   *
   * @param value raw text to encode
   * @return Base64URL-encoded string without padding
   */
  private String encodeBase64Url(String value) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Adds a non-critical unsupported header parameter to the top-level JOSE header.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @return updated JOSE header JSON
   */
  private String addUnknownHeaderParameter(String rawHeaderJson) {
    var header = parseJsonObject(rawHeaderJson, "JOSE header");
    header.put("unknown_guard_parameter", "unsupported");
    return header.toString();
  }

  /**
   * Adds an unsupported critical header parameter to the top-level JOSE header.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @return updated JOSE header JSON
   */
  private String addUnsupportedCritHeader(String rawHeaderJson) {
    var header = parseJsonObject(rawHeaderJson, "JOSE header");
    ArrayNode crit = header.putArray("crit");
    crit.add("unsupported_guard_parameter");
    header.put("unsupported_guard_parameter", "requested-by-crit");
    return header.toString();
  }

  /**
   * Removes a single top-level JOSE header parameter.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @param parameter     parameter name to remove
   * @return updated JOSE header JSON
   */
  private String removeTopLevelHeaderParameter(String rawHeaderJson, String parameter) {
    var header = parseJsonObject(rawHeaderJson, "JOSE header");
    header.remove(parameter);
    return header.toString();
  }

  /**
   * Replaces one top-level JOSE header parameter with a string value.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @param parameter     parameter name to replace
   * @param value         replacement value
   * @return updated JOSE header JSON
   */
  private String replaceTopLevelHeaderParameter(String rawHeaderJson, String parameter,
      String value) {
    var header = parseJsonObject(rawHeaderJson, "JOSE header");
    header.put(parameter, value);
    return header.toString();
  }

  /**
   * Adds a duplicate top-level {@code alg} header parameter to exercise duplicate-header rejection.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @return raw JOSE header JSON containing two {@code alg} members
   */
  private String duplicateAlgHeader(String rawHeaderJson) {
    var matcher = java.util.regex.Pattern.compile("\"alg\"\\s*:\\s*\"[^\"]+\"")
        .matcher(rawHeaderJson);
    if (!matcher.find()) {
      throw new AssertionError("Original JOSE header must contain a top-level alg parameter.");
    }

    return rawHeaderJson.substring(0, matcher.start())
        + "\"alg\":\"ES384\","
        + rawHeaderJson.substring(matcher.start());
  }

  /**
   * Adds {@code cty=JWT} to the top-level JOSE header so the payload is treated as nested JWT.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @return updated JOSE header JSON
   */
  private String addNestedJwtContentType(String rawHeaderJson) {
    var header = parseJsonObject(rawHeaderJson, "JOSE header");
    header.put("cty", "JWT");
    return header.toString();
  }

  /**
   * Removes the quotes from JSON object field names while leaving values unchanged.
   *
   * <p>The returned text is intentionally no longer valid JSON, but it stays close to the original
   * JOSE header shape. This is useful for compact JWT variants that should fail the
   * well-formed-JWT check before semantic DPoP validation starts.</p>
   *
   * @param rawJson original JSON object text
   * @return JSON-like text with unquoted field names
   */
  private String removeJsonFieldNameQuotes(String rawJson) {
    var matcher = java.util.regex.Pattern.compile("([\\{,]\\s*)\"([^\"\\\\]+)\"\\s*:")
        .matcher(rawJson);
    var malformedJson = matcher.replaceAll("$1$2:");

    assertThat(malformedJson)
        .as("JSON field-name quote removal must alter the original JSON")
        .isNotEqualTo(rawJson);

    return malformedJson;
  }

  /**
   * Wraps an existing compact JWT in a newly signed outer JWS marked as nested content.
   *
   * <p>The supplied original token becomes the unchanged payload of the outer JWS, while the outer
   * JOSE header receives {@code cty=JWT}. This exercises positive recursive nested-JWT handling.</p>
   *
   * @param token original valid compact JWT that becomes the inner token
   * @param rawHeaderJson original JOSE header JSON used as the outer header template
   * @param privateKeyPem PEM encoded EC private key used to sign the outer JWS
   * @return compact nested JWT with a valid inner token
   */
  private String createNestedJwtVariantWithValidInner(
      String token, String rawHeaderJson, String privateKeyPem) {
    return signEs256CompactJwt(addNestedJwtContentType(rawHeaderJson), token, privateKeyPem);
  }

  /**
   * Creates a compact JWS variant whose signing input is modified but whose signature is left
   * untouched, so signature verification must fail.
   *
   * @param rawHeaderJson original JOSE header JSON
   * @param rawPayload    original JWS payload JSON
   * @param signaturePart original signature segment
   * @return compact token with invalid signature
   */
  private String createInvalidSignatureVariant(String rawHeaderJson, String rawPayload,
      String signaturePart) {
    var payload = parseJsonObject(rawPayload, "JWT payload");
    payload.put("broken_signature_marker", true);
    return encodeBase64Url(rawHeaderJson) + "." + encodeBase64Url(payload.toString()) + "."
        + signaturePart;
  }

  /**
   * Parses a JSON object and raises a dedicated assertion error if parsing fails or the root node
   * is not an object.
   *
   * @param rawJson      JSON text to parse
   * @param description  human-readable description for error messages
   * @return parsed JSON object
   */
  private ObjectNode parseJsonObject(String rawJson, String description) {
    ObjectMapper objectMapper = new ObjectMapper();
    try {
      return (ObjectNode) objectMapper.readTree(rawJson);
    } catch (JsonProcessingException e) {
      throw new AssertionError("Failed to parse " + description + " as JSON object.", e);
    } catch (ClassCastException e) {
      throw new AssertionError(description + " must be a JSON object.", e);
    }
  }

  /**
   * Signs an arbitrary compact JWS using ES256 and the supplied raw header / payload strings.
   *
   * <p>This helper intentionally signs the already-serialized JOSE header string so it can be used
   * for edge cases such as missing or duplicate top-level header parameters.</p>
   *
   * @param rawHeaderJson raw JOSE header JSON
   * @param rawPayload    raw payload text
   * @param privateKeyPem PEM encoded EC private key
   * @return compact ES256 JWS
   */
  private String signEs256CompactJwt(String rawHeaderJson, String rawPayload, String privateKeyPem) {
    var signingInput = encodeBase64Url(rawHeaderJson) + "." + encodeBase64Url(rawPayload);
    var privateKey = loadEcPrivateKey(privateKeyPem);

    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);
      signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      var derSignature = signature.sign();
      var joseSignature = derToJoseEcdsaSignature(derSignature, 64);
      return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(
          joseSignature);
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Failed to sign ES256 JWT variant: " + e.getMessage(), e);
    }
  }

  /**
   * Loads a PKCS#8 EC private key from PEM text or raw Base64 content.
   *
   * @param privateKeyPem PEM encoded private key or raw Base64 key content
   * @return parsed EC private key
   */
  private ECPrivateKey loadEcPrivateKey(String privateKeyPem) {
    var normalizedPem = normalizePrivateKeyPem(privateKeyPem);
    var keyMaterial = normalizedPem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s", "");

    try {
      var encoded = Base64.getDecoder().decode(keyMaterial);
      var keySpec = new PKCS8EncodedKeySpec(encoded);
      return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(keySpec);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new AssertionError("Failed to parse EC private key for JWT variant creation.", e);
    }
  }

  /**
   * Normalizes PEM input so the loader accepts both full PEM blocks and raw Base64 payloads.
   *
   * @param privateKeyPem raw private key content from the test context
   * @return canonical PEM representation
   */
  private String normalizePrivateKeyPem(String privateKeyPem) {
    var trimmed = privateKeyPem == null ? "" : privateKeyPem.trim();
    if (trimmed.isEmpty()) {
      throw new AssertionError("Private key for JWT variant creation must not be empty.");
    }
    if (trimmed.contains("-----BEGIN PRIVATE KEY-----")) {
      return trimmed;
    }
    return "-----BEGIN PRIVATE KEY-----\n" + trimmed + "\n-----END PRIVATE KEY-----";
  }

  /**
   * Converts a DER-encoded ECDSA signature into the raw JOSE {@code R || S} representation.
   *
   * @param derSignature DER-encoded ECDSA signature
   * @param outputLength expected JOSE signature length in bytes
   * @return raw JOSE signature bytes
   */
  private byte[] derToJoseEcdsaSignature(byte[] derSignature, int outputLength) {
    try {
      ASN1Sequence sequence = ASN1Sequence.getInstance(derSignature);
      if (sequence.size() != 2) {
        throw new AssertionError("Invalid DER ECDSA signature component count: "
            + sequence.size());
      }

      var r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue();
      var s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue();
      int partLength = outputLength / 2;
      var joseSignature = new byte[outputLength];
      copyUnsignedBigInteger(r, joseSignature, 0, partLength);
      copyUnsignedBigInteger(s, joseSignature, partLength, partLength);
      return joseSignature;
    } catch (IllegalArgumentException e) {
      throw new AssertionError("Failed to convert DER ECDSA signature to JOSE format.", e);
    }
  }

  /**
   * Copies a positive big integer into a fixed-length unsigned byte slot.
   *
   * @param value      positive integer to serialize
   * @param target     target byte array
   * @param offset     target offset in bytes
   * @param fieldSize  fixed field size in bytes
   */
  private void copyUnsignedBigInteger(BigInteger value, byte[] target, int offset, int fieldSize) {
    var source = value.toByteArray();
    int sourceOffset = source.length > fieldSize ? source.length - fieldSize : 0;
    int length = source.length - sourceOffset;
    System.arraycopy(source, sourceOffset, target, offset + fieldSize - length, length);
  }

}
