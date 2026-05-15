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

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.zeta.services.TlsTestToolServiceFactory;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.ParameterType;
import io.cucumber.java.de.Dann;
import io.cucumber.java.de.Gegebensei;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.core.Serenity;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.jspecify.annotations.NonNull;
import org.opentest4j.TestAbortedException;


/**
 * Cucumber step definitions for TLS Test Tool operations.
 *
 * <p>This class provides step definitions for the TLS Tests.</p>
 */
@Slf4j
public class TlsTestToolSteps {

  /** Configuration key for the TLS test tool certificate fixture directory. */
  private static final String TLS_TEST_TOOL_CERTIFICATE_DIRECTORY_PATH_CONFIG_KEY = "tlsTestTool.certificateDirectoryPath";

  /** Configuration key for the TLS test tool CA certificate fixture. */
  private static final String TLS_TEST_TOOL_CA_CERTIFICATE_PATH_CONFIG_KEY = "tlsTestTool.caCertificatePath";

  /**
   * Supported groups required for the TLS handshake (A_28868). P-256 / P-384 and optional brainpool curves.
   */
  private static final String VALID_SUPPORTED_GROUPS = "000a000a000800170018001a001b";

  /**
   * RSA based SignatureHash Algorithms RSA_MD5, RSA_SHA1, RSA_SHA224, RSA_SHA256, RSA_SHA384 and RSA_SHA512.
   */
  private static final String RSA_HASH_VARIANTS = "000d000e000C010102010301040105010601";

  /**
   * SignatureHash Algorithms RSA_SHA256, RSA_SHA384, RSA_SHA512, DSA_SHA256, DSA_SHA384, DSA_SHA512, ECDSA_SHA256, ECDSA_SHA384,
   * ECDSA_SHA512.
   */
  private static final String SUPPORTED_SIGNATURE_HASH_ALGOS = "000d00140012040105010601040205020602040305030603";

  /**
   * Unsupported SignatureHash Algorithms RSA_MD5, RSA_SHA1, RSA_SHA224, DSA_MD5, DSA_SHA1, DSA_SHA224, ECDSA_MD5, ECDSA_SHA1,
   * ECDSA_SHA224.
   */
  private static final String UNSUPPORTED_SIGNATURE_HASH_ALGOS = "000d00140012010102010301010202020302010302030303";

  /**
   * The OID of the brainpoolP256r1 curve.
   */
  private static final String OID_BRAINPOOL256R1 = "1.3.36.3.3.2.8.1.1.7";

  /**
   * The OID of the brainpoolP384r1 curve.
   */
  private static final String OID_BRAINPOOL384R1 = "1.3.36.3.3.2.8.1.1.11";

  /**
   * The OID of the brainpoolP512r1 curve.
   */
  private static final String OID_BRAINPOOL512R1 = "1.3.36.3.3.2.8.1.1.13";

  /**
   * The OID of the P-256 / secp256r1 / prime256v1 curve.
   */
  private static final String OID_P256 = "1.2.840.10045.3.1.7";

  /**
   * The OID of the P-384 / secp384r1 curve.
   */
  private static final String OID_P384 = "1.3.132.0.34";

  /**
   * The marker to indicate that renegotiation has started.
   */
  private static final String RENEG_MARKER = "Performing renegotiation.";

  /**
   * The marker to indicate that the handshake is complete.
   */
  private static final String FINISHED_MARKER = "Valid Finished message received.";

  /**
   * TLS extension type: supported_groups.
   */
  private static final int TLS_EXTENSION_SUPPORTED_GROUPS = 0x000A;

  /**
   * TLS extension type: signature_algorithms.
   */
  private static final int TLS_EXTENSION_SIGNATURE_ALGORITHMS = 0x000D;

  /**
   * TLS extension type: supported_versions.
   */
  private static final int TLS_EXTENSION_SUPPORTED_VERSIONS = 0x002B;

  /**
   * TLS extension type: key_share.
   */
  private static final int TLS_EXTENSION_KEY_SHARE = 0x0033;

  /**
   * TLS extension type: renegotiation_info.
   */
  private static final int TLS_EXTENSION_RENEGOTIATION_INFO = 0xFF01;

  /**
   * Precompiled regex patterns.
   */
  private static final Pattern ALERT_LEVEL_PATTERN = Pattern.compile("Alert\\.level=([0-9a-fA-F]+)");
  private static final Pattern ALERT_DESCRIPTION_PATTERN = Pattern.compile("Alert\\.description=([0-9a-fA-F]+)");
  private static final Pattern TLS_HANDSHAKE_FAILED_PATTERN = Pattern.compile("TLS handshake failed:.*");
  private static final Pattern TLS_CIPHER_SUITE_PATTERN = Pattern.compile("Cipher suite:\\s*(.+)");
  private static final Pattern TLS_HASH_ALGORITHM_PATTERN = Pattern.compile("Server used HashAlgorithm\\s+(\\d+)");
  private static final Pattern TLS_SIGNATURE_ALGORITHM_PATTERN = Pattern.compile("Server used SignatureAlgorithm\\s+(\\d+)");
  private static final Pattern TLS_CERTIFICATE_VERIFY_ALGORITHM_PATTERN =
      Pattern.compile("CertificateVerify\\.algorithm=([0-9a-fA-F]{2})\\s+([0-9a-fA-F]{2})");
  private static final Pattern TLS_SERVER_HELLO_CIPHER_SUITE_PATTERN =
      Pattern.compile("ServerHello\\.cipher_suite=([0-9a-fA-F]{2})\\s+([0-9a-fA-F]{2})");
  private static final Pattern TLS_SERVER_HELLO_KEY_SHARE_GROUP_PATTERN =
      Pattern.compile("ServerHello\\.extensions=.*\\b00\\s+33\\s+[0-9a-fA-F]{2}\\s+[0-9a-fA-F]{2}\\s+([0-9a-fA-F]{2})\\s+([0-9a-fA-F]{2})");
  private static final Pattern TLS_SERVER_KEY_EXCHANGE_NAMED_CURVE_PATTERN =
      Pattern.compile("ServerKeyExchange\\.params\\.curve_params\\.namedcurve=(\\d+)");
  private static final Pattern TLS_RENEGOTIATION_PHASE_PATTERN =
      Pattern.compile("=>\\s*renegotiate|Performing renegotiation\\.");
  private static final Pattern TLS_CLIENT_HELLO_SENT_PATTERN = Pattern.compile("ClientHello message transmitted\\.");
  private static final Pattern TLS_CLIENT_HELLO_WRITE_PATTERN = Pattern.compile("=>\\s*write client hello");
  private static final Pattern CERTIFICATE_LIST_PATTERN = Pattern.compile("Certificate\\.certificate_list\\[0\\]=([0-9a-fA-F \\t]+)");
  private static final Pattern HEX_BYTE_PATTERN = Pattern.compile("\\b[0-9a-fA-F]{2}\\b");
  private static final Pattern TCP_IP_CONNECTION_ESTABLISHED_PATTERN =
      Pattern.compile("(?m)\\bTCP/IP connection (?:to \\S+ established|from \\S+ received)\\.");
  private static final Pattern TCP_IP_CONNECTION_FAILED_PATTERN =
      Pattern.compile("(?m)\\bTCP/IP connection to .+ failed:.*");
  private static final Pattern SERVER_HELLO_EXTENSIONS_PATTERN =
      Pattern.compile("ServerHello\\.extensions\\s*=\\s*([0-9a-fA-F]{2}(?:\\s+[0-9a-fA-F]{2})*)?");
  private static final Pattern CLIENT_HELLO_EXTENSIONS_OPTIONAL_PATTERN =
      Pattern.compile("(?m)^.*ClientHello\\.extensions\\s*=\\s*([0-9a-fA-F]{2}(?:[ \\t]+[0-9a-fA-F]{2})*)?[ \\t]*$");
  private static final Pattern CLIENT_HELLO_EXTENSIONS_LINE_PATTERN =
      Pattern.compile("ClientHello\\.extensions\\s*=\\s*([0-9a-fA-F]{2}(?:[ \\t]+[0-9a-fA-F]{2})*)?[ \\t]*$");
  private static final Pattern CLIENT_HELLO_CIPHER_SUITES_PATTERN =
      Pattern.compile("(?m)^.*ClientHello\\.cipher_suites=([0-9a-fA-F]{2}(?:[ \\t]+[0-9a-fA-F]{2})*)[ \\t]*$");

  /**
   * String for storing the TLS logs.
   */
  private String tlsLogs;

  /**
   * Tracks whether a service-backed TLS test tool run was started in the current scenario.
   */
  private boolean tlsTestToolStarted;

  /**
   * Stores the TLS 1.2 hash algorithms that were intentionally offered in the previous setup step. This allows failure messages to explain
   * what was tested versus what the server selected.
   */
  private LinkedHashSet<TlsHashAlgorithm> lastOfferedTlsHashAlgorithms = new LinkedHashSet<>();

  /**
   * Build a complete SNI (server_name) extension body for a given host. Format: extension_type(2) + extension_length(2) +
   * server_name_list_length(2) + name_type(1) + host_name_length(2) + host_name.
   *
   * @param host raw host value from the feature file (host, host:port or URL)
   * @return hex encoded SNI extension including type and length fields
   */
  private static @NonNull String buildSniExtensionHex(String host) {
    var sniHost = normalizeHostForSni(host);
    var hostBytes = sniHost.getBytes(StandardCharsets.US_ASCII);
    var serverNameLen = 1 + 2 + hostBytes.length;
    var extensionDataLen = 2 + serverNameLen;

    var sb = new StringBuilder();
    sb.append("0000"); // server_name extension type
    sb.append(String.format("%04x", extensionDataLen));
    sb.append(String.format("%04x", serverNameLen));
    sb.append("00"); // host_name
    sb.append(String.format("%04x", hostBytes.length));
    for (var b : hostBytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   * Resolve host-only value for SNI. Accept plain host, host:port or URL.
   *
   * @param host raw host value from the scenario
   * @return normalized host without scheme or port
   */
  private static @NonNull String normalizeHostForSni(String host) {
    var candidate = host.trim();
    if (candidate.startsWith("[")) {
      var closingBracket = candidate.indexOf(']');
      if (closingBracket > 1) {
        return candidate.substring(1, closingBracket);
      }
    }
    if (candidate.contains("://")) {
      try {
        var uri = new URI(candidate);
        if (uri.getHost() != null && !uri.getHost().isBlank()) {
          return uri.getHost();
        }
      } catch (URISyntaxException ignored) {
        // Fallback below.
      }
    }
    var colonCount = candidate.chars().filter(ch -> ch == ':').count();
    if (colonCount > 1) {
      // Plain IPv6 literal without scheme/port.
      return candidate;
    }
    if (candidate.contains(":") && !candidate.startsWith("[")) {
      return candidate.substring(0, candidate.indexOf(':'));
    }
    return candidate;
  }

  /**
   * Builds a client-side TLS 1.2 test tool configuration.
   *
   * @param tlsClientHelloExtensions hex content for manipulated ClientHello extensions
   * @param tlsSupportedGroups hex content for the supported_groups extension
   * @param tlsCipherSuites tls-test-tool formatted cipher-suite configuration line
   * @param host host to be tested
   * @return tls-test-tool client configuration
   */
  private static @NonNull String getTls12TestToolConfigBuffer(String tlsClientHelloExtensions, String tlsSupportedGroups,
                                                              String tlsCipherSuites, String host) {
    var basicConfiguration = """
        # TLS Test Tool configuration file
        mode=client
        tlsLibrary=mbed TLS
        waitBeforeClose=5
        logLevel=low
        tlsVersion=(3,3)
        handshakeType=normal
        tlsSecretFile=tlsSecretFile.txt
        """;
    // We manipulate extensions intentionally for several tests. Keep SNI present explicitly,
    // because replacing the extension block can otherwise remove it and cause generic
    // protocol-version alerts from ingress/frontends before crypto checks are reached.
    var sniExtension = buildSniExtensionHex(host);
    var manipulateClientHelloExtensions = "manipulateClientHelloExtensions="
        + sniExtension + tlsClientHelloExtensions + tlsSupportedGroups + "\n";
    var port = "port=443\n";
    return basicConfiguration
        + tlsCipherSuites
        + manipulateClientHelloExtensions
        + port
        + "host=" + host + "\n";
  }

  /**
   * Builds a TLS-1.3 client-side TLS test tool configuration.
   *
   * @param tlsSignatureSchemes tls-test-tool formatted TLS-1.3 signature-schemes value
   * @param tlsSupportedGroups TLS-1.3 supported_groups value
   * @param tlsCipherSuites tls-test-tool formatted cipher-suite configuration line
   * @param host host to be tested
   * @return tls-test-tool client configuration
   */
  private static @NonNull String getTls13TestToolConfigBuffer(String tlsSignatureSchemes, String tlsSupportedGroups,
      String tlsCipherSuites, String host) {
    var basicConfiguration = """
        # TLS Test Tool configuration file
        mode=client
        tlsLibrary=OpenSSL
        waitBeforeClose=5
        logLevel=low
        tlsUseSni=true
        tlsVersion=(3,4)
        handshakeType=normal
        tlsSecretFile=tlsSecretFile.txt
        """;

    var port = "port=443\n";
    return basicConfiguration
        + "tlsCipherSuites=" + tlsCipherSuites + "\n"
        + "tlsSupportedGroups=" + tlsSupportedGroups + "\n"
        + "tlsSignatureSchemes=" + tlsSignatureSchemes + "\n"
        + port
        + "host=" + host + "\n";
  }

  /**
   * Builds a default TLS Test Tool server configuration with additional cipher-suite configuration.
   *
   * @param tlsCipherSuites tls-test-tool formatted cipher-suite configuration line
   * @return tls-test-tool server configuration
   */
  private static @NonNull String getTlsTestToolServerBaseConfig(String tlsCipherSuites) {
    return getTlsTestToolServerBaseConfig()
        + tlsCipherSuites;
  }

  /**
   * Builds a default TLS Test Tool server configuration.
   *
   * @return tls-test-tool server configuration for mbed TLS
   */
  private static @NonNull String getTlsTestToolServerBaseConfig() {
    return getTlsTestToolServerBaseConfig(TlsLibrary.MBED_TLS);
  }

  /**
   * Builds a default TLS Test Tool server configuration.
   *
   * @param tlsLib            TLS library used by tls-test-tool
   * @return tls-test-tool server configuration
   */
  private static @NonNull String getTlsTestToolServerBaseConfig(TlsLibrary tlsLib) {

    // Get the TLS Test Tool Server Port from the deployment configuration
    String tlsTestToolPort = TigerGlobalConfiguration.readStringOptional("tlsTestTool.port")
        .orElse("");

    if (tlsTestToolPort.isBlank()) {
      throw new AssertionError("TLS test tool configuration tlsTestTool.port could not be resolved.");
    }

    String basicConfiguration = """
        # TLS Test Tool configuration file
        host=0.0.0.0
        waitBeforeClose=5
        logLevel=low
        listenTimeout=60
        tlsVersion=(3,3)
        mode=server
        tlsSecretFile=tlsSecretFile.txt
        """;
    String library = "tlsLibrary=" + tlsLib.getDisplayName() + "\n";
    String port = "port=" + tlsTestToolPort + "\n";
    return basicConfiguration
        + library
        + port;
  }

  /**
   * Builds a default TLS 1.3 TLS Test Tool server configuration.
   *
   * @param tlsLib TLS library used by tls-test-tool
   * @return tls-test-tool server configuration
   */
  private static @NonNull String getTls13TestToolServerBaseConfig(TlsLibrary tlsLib) {
    return getTlsTestToolServerBaseConfig(tlsLib)
        .replace("tlsVersion=(3,3)\n", "tlsVersion=(3,4)\n");
  }

  /**
   * Builds the default TLS 1.2 cipher-suite list used for broad positive handshake tests.
   *
   * @return tls-test-tool formatted cipher-suite configuration line
   */
  private static @NonNull String getTls12TestValidCipherSuites() {
    log.info(
        """
            The TLS 1.2 ClientHello offers the following supported TLS 1.2 cipher suites (also those in accordance with TR-02102-2, Chapter 3.3.1 Table 2):
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            TLS_ECDHE_ECDSA_WITH_AES_128_CCM
            TLS_ECDHE_ECDSA_WITH_AES_256_CCM
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
            TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
            TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
            TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            TLS_DHE_RSA_WITH_AES_128_CCM
            TLS_DHE_RSA_WITH_AES_256_CCM""");

    return
        "tlsCipherSuites=(0xC0,0x23),(0xC0,0x24),(0xC0,0x2B),(0xC0,0x2C),(0xC0,0xAC),(0xC0,0xAD),"
            + "(0xC0,0x27),(0xC0,0x28),(0xC0,0x2F),(0xC0,0x30),(0x00,0x40),(0x00,0x6A),(0x00,0xA2),"
            + "(0x00,0xA3),(0x00,0x67),(0x00,0x6B),(0x00,0x9E),(0x00,0x9F),(0xC0,0x9E),(0xC0,0x9F)\n";

  }

  /**
   * Builds the default TLS 1.3 cipher-suite list used for broad positive handshake tests.
   *
   * @return tls-test-tool formatted cipher-suite configuration line
   */
  private static @NonNull String getTls13TestValidCipherSuites() {
    var mandatoryTls13CipherSuites = TlsCipherSuite.mandatoryTls13CipherSuites();

    log.info("The TLS 1.3 ClientHello offers the following mandatory TLS 1.3 cipher suites in accordance with A_28868:");
    mandatoryTls13CipherSuites.stream()
        .map(TlsCipherSuite::getCipherSuiteName)
        .forEach(log::info);

    return mandatoryTls13CipherSuites.stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.joining(","));
  }

  /**
   * Builds the TLS 1.2 ECDHE-only cipher-suite list for curve-focused tests.
   *
   * @return tls-test-tool formatted cipher-suite configuration line
   */
  private static @NonNull String getTls12TestValidEcdheCipherSuites() {
    log.info(
        """
            The TLS 1.2 ClientHello offers the following supported ECDHE TLS 1.2 cipher suites (also those in accordance with TR-02102-2, Chapter 3.3.1 Table 2):
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            TLS_ECDHE_ECDSA_WITH_AES_128_CCM
            TLS_ECDHE_ECDSA_WITH_AES_256_CCM
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384""");

    return "tlsCipherSuites=(0xC0,0x23),(0xC0,0x24),(0xC0,0x2B),(0xC0,0x2C),(0xC0,0xAC),(0xC0,0xAD),"
        + "(0xC0,0x27),(0xC0,0x28),(0xC0,0x2F),(0xC0,0x30)\n";

  }

  /**
   * Builds a tls-test-tool signature/hash configuration value from the provided TLS 1.2 hashes.
   *
   * <p>The tls-test-tool expects tuples in the form {@code (signature,hash)}.
   * This helper pairs each requested hash with every signature algorithm that is permitted by policy
   * for the current tests.</p>
   *
   * @param hashes insertion-ordered set of TLS 1.2 hash algorithms to advertise
   * @return comma-separated tuple list suitable for {@code tlsSignatureAlgorithms=...}
   */
  private static @NonNull String buildTls12SupportedSignatureHashPairs(LinkedHashSet<TlsHashAlgorithm> hashes) {
    if (hashes == null || hashes.isEmpty()) {
      throw new AssertionError("At least one TLS 1.2 hash algorithm is required.");
    }

    var supportedSignatureAlgos = TlsSignatureAlgorithm.getSupportedSignatureAlgorithms();
    return hashes.stream()
        .flatMap(hashAlgorithm -> supportedSignatureAlgos.stream()
            .map(signatureAlgorithm -> "(" + signatureAlgorithm.getValue() + "," + hashAlgorithm.getValue() + ")"))
        .collect(Collectors.joining(","));
  }

  /**
   * Parses DER-encoded certificate bytes as an {@link X509Certificate}.
   *
   * @param der certificate bytes in DER format
   * @return parsed {@link X509Certificate}
   * @throws CertificateException if parsing fails
   */
  private static X509Certificate parseAsX509(byte[] der) throws CertificateException {
    var cf = CertificateFactory.getInstance("X.509");
    try (InputStream in = new ByteArrayInputStream(der)) {
      var c = cf.generateCertificate(in);
      if (!(c instanceof X509Certificate x509)) {
        throw new AssertionError(
            "Parsed certificate is not an X509Certificate (type=" + c.getType() + ")");
      }
      return x509;
    } catch (IOException ioe) {
      // Should not happen with ByteArrayInputStream, but keep it clean
      throw new CertificateException("I/O error while parsing certificate", ioe);
    }
  }

  /**
   * Extracts the certificate bytes from the log line with Certificate.certificate_list[0]=...
   *
   * @param fullLog full TLS log content
   * @return DER certificate bytes or {@code null} if not present
   */
  private static byte[] extractCertificateFromLog(String fullLog) {
    if (fullLog == null || fullLog.isBlank()) {
      return null;
    }

    var m = CERTIFICATE_LIST_PATTERN.matcher(fullLog);
    if (!m.find()) {
      return null;
    }

    var raw = m.group(1);
    var b = HEX_BYTE_PATTERN.matcher(raw);
    var byteCount = 0;
    while (b.find()) {
      byteCount++;
    }
    if (byteCount == 0) {
      return null;
    }
    var normalized = new StringBuilder(byteCount * 2);
    b.reset();
    while (b.find()) {
      normalized.append(b.group());
    }
    try {
      return Hex.decodeHex(normalized.toString());
    } catch (DecoderException e) {
      return null;
    }
  }

  /**
   * Extracts the named curve OID from the certificate.
   *
   * @param cert X509 certificate
   * @return named curve OID (e.g. "1.2.840.10045.3.1.7") or null if not EC / not named curve
   */
  private static String getNamedCurveOid(X509Certificate cert) {

    if (cert == null) {
      return null;
    }

    var pk = cert.getPublicKey();

    if (!(pk instanceof ECPublicKey)) {
      return null;
    }
    try {

      var spki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());

      // AlgorithmIdentifier parameters for id-ecPublicKey are typically the namedCurve OID
      if (!spki.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
        return null;
      }

      var params = spki.getAlgorithm().getParameters();
      if (params == null) {
        return null;
      }

      var curveOid = ASN1ObjectIdentifier.getInstance(params);
      return curveOid.getId();

    } catch (NullPointerException | IllegalArgumentException | ASN1ParsingException e) {
      return null;
    }
  }

  /**
   * Resolves a TLS supported group from a certificate curve OID.
   *
   * @param curveOid EC named-curve OID from the certificate
   * @return matching supported group or {@link TlsSupportedGroup#UNKNOWN}
   */
  private static TlsSupportedGroup getSupportedGroupFromCurveOid(String curveOid) {
    if (curveOid == null || curveOid.isBlank()) {
      return TlsSupportedGroup.UNKNOWN;
    }
    return switch (curveOid) {
      case OID_P256 -> TlsSupportedGroup.SECP256R1;
      case OID_P384 -> TlsSupportedGroup.SECP384R1;
      case OID_BRAINPOOL256R1 -> TlsSupportedGroup.BRAINPOOLP256R1;
      case OID_BRAINPOOL384R1 -> TlsSupportedGroup.BRAINPOOLP384R1;
      case OID_BRAINPOOL512R1 -> TlsSupportedGroup.BRAINPOOLP512R1;
      default -> TlsSupportedGroup.UNKNOWN;
    };
  }

  /**
   * Resolve the certificate path.
   *
   * @param certificate certificate or key file name
   * @return resolved file path, converted to WSL format if required
   */
  private static String resolveCertificateOrKeyPath(String certificate) {

    if (certificate == null || certificate.isBlank()) {
      throw new AssertionError("The certificate is empty or null.");
    }

    var configuredPath = TigerGlobalConfiguration.readStringOptional(TLS_TEST_TOOL_CERTIFICATE_DIRECTORY_PATH_CONFIG_KEY)
        .orElseThrow(() -> new AssertionError(
            "The config key '" + TLS_TEST_TOOL_CERTIFICATE_DIRECTORY_PATH_CONFIG_KEY + "' could not be resolved."));
    var baseDirectory = Path.of(System.getProperty("user.dir"), configuredPath).normalize();
    var certificateLocation = baseDirectory.resolve(certificate).normalize();
    if (!certificateLocation.startsWith(baseDirectory)) {
      throw new AssertionError("The certificate path is invalid.");
    }

    return certificateLocation.toString();
  }

  /**
   * Resolves the CA certificate path used by the TLS test tool service.
   *
   * @return resolved CA certificate file path
   */
  private static Path resolveCaCertificatePath() {
    var configuredPath = TigerGlobalConfiguration.readStringOptional(TLS_TEST_TOOL_CA_CERTIFICATE_PATH_CONFIG_KEY)
        .orElseThrow(() -> new AssertionError(
            "The config key '" + TLS_TEST_TOOL_CA_CERTIFICATE_PATH_CONFIG_KEY + "' could not be resolved."));
    return Path.of(System.getProperty("user.dir"), configuredPath).normalize();
  }

  /**
   * Configures and runs the TLS test tool (server) for TLS 1.1.
   *
   */
  @Gegebensei("die TlsTestTool-Server-Konfigurationsdaten wurden nur für TLS 1.1 erstellt")
  @Given("the TlsTestTool server configuration data with only TLS 1.1 is created")
  public void setTls12TlsTestToolServerConfigForTls1_1() {

    String tlsTestToolConfigBuffer = getTlsTestToolServerBaseConfig()
        + "manipulateHelloVersion=(0x03,0x02)\n";

    log.info("The Server only offers a TLS 1.1 connection.");

    runTlsTestToolServer(tlsTestToolConfigBuffer);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.1.
   *
   * @param host Host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} wurden nur für TLS 1.1 erstellt")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} with only TLS 1.1 is created")
  public void setTls12TlsTestToolConfigForTls1_1(String host) {
    checkHost(host);

    var basicConfiguration = """
        # TLS Test Tool configuration file
        mode=client
        tlsLibrary=mbed TLS
        waitBeforeClose=5
        logLevel=low
        tlsVersion=(3,2)
        tlsUseSni=true
        handshakeType=normal
        tlsSecretFile=tlsSecretFile.txt
        """;
    var port = "port=443\n";
    var tlsTestToolConfigBuffer = basicConfiguration
        + port
        + "host=" + host + "\n";

    log.info("The Client only offers a TLS 1.1 connection.");

    runTlsTestToolClient(tlsTestToolConfigBuffer);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.3 with non-recommended signature schemes.
   *
   * @param host host to be tested
   * @param signatureSchemes signature schemes that are expected to be non-recommended for TLS 1.3
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden nicht empfehlende TLS 1.3 Signature-Schemes wurden festgelegt:")
  @Given("the TLS 1.3 TlsTestTool configuration data for the host {tigerResolvedString} has been set for the following non recommended TLS 1.3 signature schemes:")
  public void setTls13TlsTestToolConfigForNonRecommendedSignatureSchemes(String host,
      DataTable signatureSchemes) {
    checkHost(host);
    if (signatureSchemes == null) {
      throw new AssertionError("The signature schemes table is null.");
    }

    // Check if all non-recommended TLS 1.3 signature schemes are present
    var signatureSchemeHashSet = parseNonEmptyFirstColumn(signatureSchemes, HashSet::new);

    var nonRecommendedSignatureSchemes = TlsSignatureSchemes.nonRecommendedSchemeNames();

    if (!nonRecommendedSignatureSchemes.equals(signatureSchemeHashSet)) {
      throw new AssertionError("""
          For this test, the signature hash algorithms cannot be changed.
          They must be:
          - rsa_pkcs1_sha256
          - rsa_pkcs1_sha384
          - rsa_pkcs1_sha512""");
    }

    log.info(
        "The TLS 1.3 ClientHello offers the following TLS 1.3 cipher suites in accordance with A_28868");
    log.info("TLS_AES_128_GCM_SHA256");
    log.info("TLS_AES_256_GCM_SHA384");

    var mandatoryCipherSuites = TlsCipherSuite.mandatoryTls13CipherSuites().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.joining(","));

    runTls13ClientScenario(
        host,
        mandatoryCipherSuites,
        nonRecommendedSignatureSchemes,
        TlsSignatureSchemes.nonRecommendedSchemeHexValues(),
        TlsSupportedGroup.tls13SupportedGroups());
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.3 with the signature schemes from the scenario.
   *
   * <p>This scenario currently expects the recommended TLS-1.3 signature-scheme set.</p>
   *
   * @param host host to be tested
   * @param signatureSchemes TLS-1.3 signature schemes provided by the scenario
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden TLS 1.3 Signature-Schemes wurden festgelegt:")
  @Given("the TLS 1.3 TlsTestTool configuration data for the host {tigerResolvedString} has been set for the following TLS 1.3 signature schemes:")
  public void setTls13TlsTestToolConfigSignatureSchemes(String host,
                                                        DataTable signatureSchemes) {
    checkHost(host);
    if (signatureSchemes == null) {
      throw new AssertionError("The signature schemes table is null.");
    }

    log.info(
        "The TLS 1.3 ClientHello offers the following TLS 1.3 cipher suites in accordance with A_28868");
    log.info("TLS_AES_128_GCM_SHA256");
    log.info("TLS_AES_256_GCM_SHA384");

    var mandatoryCipherSuites = TlsCipherSuite.mandatoryTls13CipherSuites().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.joining(","));

    // Convert the scenario-provided TLS 1.3 signature schemes to tls-test-tool wire values.
    var signatureSchemeHashSet = parseNonEmptyFirstColumn(signatureSchemes, HashSet::new);
    var signatureSchemeHexValues = TlsSignatureSchemes.schemeHexValuesForSchemeNames(signatureSchemeHashSet);
    runTls13ClientScenario(
        host,
        mandatoryCipherSuites,
        signatureSchemeHashSet,
        signatureSchemeHexValues,
        TlsSupportedGroup.tls13SupportedGroups());
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.2 with unsupported RSA Signature and hash algorithms.
   *
   * @param host                    Host to be tested
   * @param signatureHashAlgorithms Signature and hash algorithms that must not be supported
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden TLS 1.2 Signatur-Hash-Algorithmen wurden festgelegt:")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} has been set for the following TLS 1.2 signature hash algorithms:")
  public void setTls12TlsTestToolConfigForUnsupportedSignatureHashAlgorithms(String host,
      DataTable signatureHashAlgorithms) {

    checkHost(host);
    if (signatureHashAlgorithms == null) {
      throw new AssertionError("The signature hash algorithms table is null.");
    }

    // Check if all the supported/mandatory SignatureAndHashAlgorithms are present
    var signatureAlgorithmHashSet = parseNonEmptyFirstColumn(signatureHashAlgorithms, HashSet::new);

    var supportedSignatureAndHashAlgorithms = Arrays.stream(SignatureAndHashAlgorithms.values())
        .map(Enum::toString)
        .collect(Collectors.toCollection(HashSet::new));

    if (!supportedSignatureAndHashAlgorithms.equals(signatureAlgorithmHashSet)) {
      throw new AssertionError("""
          For this test, the signature hash algorithms cannot be changed.
          They must be:
          - RSA_MD5
          - RSA_SHA1
          - RSA_SHA224
          - RSA_SHA256
          - RSA_SHA384
          - RSA_SHA512""");
    }

    runTls12ClientScenario(
        host,
        getTls12TestValidCipherSuites(),
        RSA_HASH_VARIANTS,
        VALID_SUPPORTED_GROUPS,
        supportedSignatureAndHashAlgorithms,
        false);
  }

  /**
   * Checks whether a TLS “alert” has been received.
   */
  @Dann("akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id {string}")
  @Dann("akzeptiert der ZETA Client das ServerHello nicht und sendet eine Alert Nachricht mit Description Id {string}")
  @Dann("der ZETA Client sendet eine Alert Nachricht mit Description Id {string}")
  @Then("the Zeta Guard endpoint does not accept the ClientHello and sends an alert message with the description id {string}")
  @Then("the Zeta Client does not accept the ServerHello and sends an alert message with the description id {string}")
  @Then("the Zeta Client sends an alert message with the description id {string}")
  public void endpointSendsAlertWithDescription(String descriptionId) {
    requireTlsLogs();

    // Check the logs for the "Alert message received" and "Alert.level=02" alert messages
    Assertions
        .assertThat(tlsLogs.contains("Alert message received"))
        .withFailMessage(
            "'Alert' message not received from endpoint. %s %s",
            extractAlertSummary(),
            buildHashNegotiationSummary())
        .isTrue();
    Assertions
        // Alert.level=02 indicates a fatal alert
        .assertThat(tlsLogs.contains("Alert.level=02"))
        .withFailMessage(
            "'Alert.level=02' not found in TLS logs. %s %s",
            extractAlertSummary(),
            buildHashNegotiationSummary())
        .isTrue();
    Assertions
        .assertThat(tlsLogs.contains("Alert.description=" + descriptionId))
        .withFailMessage(
            "Alert.description=%s not found in TLS logs. %s %s",
            descriptionId,
            extractAlertSummary(),
            buildHashNegotiationSummary())
        .isTrue();
  }

  /**
  /**
   * Configures and runs the TLS test tool for TLS 1.2.
   *
   * @param host Host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString}")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString}")
  public void setValidTlsTestToolConfig(String host) {
    var tlsCipherSuites = getTls12TestValidCipherSuites();
    runTls12TestTool(host, tlsCipherSuites);
  }

  /**
   * Checks whether a ServerHello record was not received.
   */
  @Dann("wird der ServerHello-Record nicht empfangen")
  @Then("the ServerHello record is not received")
  public void checkIfTheServerHelloIsNotReceived() {
    requireTlsLogs();

    var p = Pattern.compile(
        "ServerHello\\.cipher_suite\\s*=\\s*([0-9a-fA-F]{2})\\s+([0-9a-fA-F]{2})");
    var m = p.matcher(tlsLogs);

    var hi = 0;
    var lo = 0;
    if (m.find()) {
      hi = Integer.parseInt(m.group(1), 16);
      lo = Integer.parseInt(m.group(2), 16);
    }

    Assertions
        .assertThat(!(tlsLogs.contains("ServerHello.cipher_suite")))
        .withFailMessage("ServerHello message received where not expected. "
            + "Server selected cipher suite (0x%x,0x%x).", hi, lo)
        .isTrue();
  }

  /**
   * Checks whether no Server Key Exchange record is sent.
   */
  @Dann("wird der Server-Key-Exchange-Datensatz nicht gesendet")
  @Then("the server key exchange record is not sent")
  public void checkIfTheServerKeyExchangeIsNotSent() {
    requireTlsLogs();
    Assertions
        .assertThat(!(tlsLogs.contains("ServerKeyExchange.params.curve_params.namedcurve")
            || tlsLogs.contains("Bad ServerKeyExchange message received")))
        .withFailMessage("ServerKeyExchange message received.")
        .isTrue();
  }

  /**
   * Checks whether a Server Key exchange record is sent.
   */
  @Dann("wird der Server-Key-Exchange-Datensatz gesendet")
  @Then("the server key exchange record is sent")
  public void checkIfTheServerKeyExchangeIsSent() {
    requireTlsLogs();
    Assertions
        .assertThat(tlsLogs.contains("ServerKeyExchange.params.curve_params.namedcurve"))
        .withFailMessage("ServerKeyExchange message not received.")
        .isTrue();
  }

  /**
   * Skips TLS 1.3 scenarios when the endpoint does not support TLS 1.3.
   *
   * <p>If the log indicates protocol-version rejection, the scenario is aborted as skipped. Other failures are
   * left to subsequent assertions so real conformance bugs still fail the scenario.</p>
   */
  @Dann("wird TLS 1.3 unterstützt oder das Szenario wird übersprungen")
  @Then("TLS 1.3 is supported or the scenario is skipped")
  public void skipScenarioIfTls13IsNotSupportedByTheServer() {
    requireTlsLogs();

    if (tlsLogs.contains("Alert.description=46")
        || tlsLogs.toLowerCase(Locale.ROOT).contains("protocol version")) {
      throw new TestAbortedException("TLS 1.3 is not supported by the tested endpoint.");
    }
  }

  /**
   * Checks whether the ClientHello advertises TLS 1.3 via the supported_versions extension and skips
   * the scenario otherwise.
   */
  @Dann("der ClientHello-Record signalisiert TLS 1.3 Unterstützung oder das Szenario wird übersprungen")
  @Then("the ClientHello record signals TLS 1.3 support or the scenario is skipped")
  public void skipScenarioIfClientHelloDoesNotSignalTls13Support() {
    requireTlsLogs();

    if (!clientHelloSignalsTls13Support(tlsLogs)) {
      throw new TestAbortedException(
          "ClientHello does not advertise TLS 1.3 support via supported_versions.");
    }
  }

  /**
   * Configures and runs TLS 1.2 with the provided cipher-suite list.
   *
   * @param host                Host to be tested
   * @param cipherSuiteHexValue Hex value of the cipher suite(s) to be tested
   */
  private void configureTls12ForCipherSuites(String host, String cipherSuiteHexValue) {
    if (cipherSuiteHexValue == null || cipherSuiteHexValue.isBlank()) {
      throw new AssertionError("The Cipher Suite value is empty or null.");
    }

    var tlsCipherSuites = "tlsCipherSuites=" + cipherSuiteHexValue + "\n";
    log.info("The TLS 1.2 ClientHello offers the %s TLS 1.2 cipher suites.".formatted(cipherSuiteHexValue));
    runTls12TestTool(host, tlsCipherSuites);
  }

  /**
   * Configures and runs TLS 1.3 with the provided cipher-suite list.
   *
   * @param host Host to be tested
   * @param cipherSuiteHexValue Hex value of the cipher suite(s) to be tested
   */
  private void configureTls13ForCipherSuites(String host, String cipherSuiteHexValue) {
    checkHost(host);
    if (cipherSuiteHexValue == null || cipherSuiteHexValue.isBlank()) {
      throw new AssertionError("The Cipher Suite value is empty or null.");
    }

    log.info("The TLS 1.3 ClientHello offers the %s TLS 1.3 cipher suites.".formatted(cipherSuiteHexValue));
    runTlsTestToolClient(
        getTls13TestToolConfigBuffer(
            TlsSignatureSchemes.recommendedSchemeHexValues(),
            TlsSupportedGroup.tls13SupportedGroups(),
            cipherSuiteHexValue,
            host));
  }

  /**
   * Configures and runs TLS 1.2 with the provided cipher-suite.
   *
   * @param cipherSuiteHexValue Hex value of the cipher suite(s) to be tested
   */
  private void configureAndRunTls12ServerForCipherSuites(String cipherSuiteHexValue) {
    if (cipherSuiteHexValue == null || cipherSuiteHexValue.isBlank()) {
      throw new AssertionError("The Cipher Suite value is empty or null.");
    }

    var tlsCipherSuites = "tlsCipherSuites=" + cipherSuiteHexValue + "\n";
    log.info("The TLS 1.2 server offers the %s TLS 1.2 cipher suite.".formatted(cipherSuiteHexValue));
    runTls12TestToolServer(tlsCipherSuites);
  }

  /**
   * Verifies that a resolved cipher-suite profile belongs to the expected TLS version before using it in a
   * version-specific step definition.
   *
   * @param profile         resolved cipher-suite profile token from the feature file
   * @param expectedVersion TLS version required by the calling step
   */
  private static void requireCipherSuiteProfileVersion(TlsCipherSuite profile, TlsVersion expectedVersion) {
    if (profile == null) {
      throw new AssertionError("The cipher suite profile is null.");
    }
    if (profile.getTlsVersion() != expectedVersion) {
      throw new AssertionError("The cipher suite profile is not a " + expectedVersion.getDisplayName() + " profile.");
    }
  }

  /**
   * Resolves a readable cipher suite profile token from a feature file.
   *
   * @param cipherSuiteId cipher suite unique id (e.g. {@code ecdhe_ecdsa_aes_128_gcm_sha256})
   * @return matching cipher suite
   */
  @ParameterType("ecdhe_ecdsa_aes_128_gcm_sha256|ecdhe_ecdsa_aes_256_gcm_sha384|aes_128_gcm_sha256|aes_256_gcm_sha384")
  public TlsCipherSuite tlsCipherSuiteProfile(String cipherSuiteId) {
    return TlsCipherSuite.fromCipherSuiteId(cipherSuiteId);
  }

  /**
   * Resolves a readable server certificate token from a feature file.
   *
   * @param certificateId certificate unique id (e.g. {@code zeta_tls_test_tool_server_ecdsa_good_certificate})
   * @return matching certificate descriptor
   */
  @ParameterType(
      "zeta_tls_test_tool_server_ecdsa_private_key|zeta_tls_test_tool_server_ecdsa_different_cn_certificate|"
          + "zeta_tls_test_tool_server_ecdsa_different_san_certificate|zeta_tls_test_tool_server_ecdsa_good_certificate|"
          + "zeta_tls_test_tool_server_ecdsa_expired_certificate|zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate|"
          + "zeta_tls_test_tool_server_ecdsa_different_ca_certificate|zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate|"
          + "zeta_tls_test_tool_server_ecdsa_ocsp_responder_certificate")
  public TlsServerCertificates tlsServerCertificate(String certificateId) {
    return TlsServerCertificates.fromCertificateId(certificateId);
  }

  /**
   * Configures and runs TLS 1.2 for a readable cipher suite profile.
   *
   * @param host    Host to be tested
   * @param profile cipher suite profile mapped to tls-test-tool tuple syntax
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für das Cipher-Suite-Profil {tlsCipherSuiteProfile}")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for the cipher suite profile {tlsCipherSuiteProfile}")
  public void setValidTlsTestToolConfigForCipherSuiteProfile(String host, TlsCipherSuite profile) {
    requireCipherSuiteProfileVersion(profile, TlsVersion.TLS_1_2);
    configureTls12ForCipherSuites(host, profile.getTlsTestToolCipherSuiteValue());
  }

  /**
   * Configures and runs TLS 1.3 for a readable cipher suite profile.
   *
   * @param host Host to be tested
   * @param profile cipher suite profile mapped to tls-test-tool tuple syntax
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für das Cipher-Suite-Profil {tlsCipherSuiteProfile}")
  @Given("the TLS 1.3 TlsTestTool configuration data for the host {tigerResolvedString} for the cipher suite profile {tlsCipherSuiteProfile}")
  public void setValidTlsTestToolConfigForTls13CipherSuiteProfile(String host, TlsCipherSuite profile) {
    requireCipherSuiteProfileVersion(profile, TlsVersion.TLS_1_3);
    configureTls13ForCipherSuites(host, profile.getTlsTestToolCipherSuiteValue());
  }

  /**
   * Configures and runs TLS 1.2 for a specific group.
   *
   * @param supportedGroup The supported group
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützte Gruppe {string}")
  @Given("the TLS 1.2 TlsTestTool server configuration data for the Supported group {string}")
  public void setValidTls12TlsTestToolServerConfigForSupportedGroup(String supportedGroup) {

    if (supportedGroup == null || supportedGroup.isBlank()) {
      throw new AssertionError("The Supported group value is empty or null.");
    }

    var group = TlsSupportedGroup.fromDisplayName(supportedGroup);
    if (group == TlsSupportedGroup.UNKNOWN) {
      throw new AssertionError("The Supported Group value is unknown.");
    }

    var tlsTestToolConfigBuffer = getTlsTestToolServerBaseConfig()
        + "manipulateEllipticCurveGroup=" + group.getDisplayName() + "\n";

    runTls12TestToolServer(tlsTestToolConfigBuffer);
  }

  /**
   * Configures and runs TLS 1.2 for a specific hash.
   *
   * @param hashAlgo The hash algorithm
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für den Hash-Algorithmus {string}")
  @Given("the TLS 1.2 TlsTestTool server configuration data for the Hash-Algo {string}")
  public void setValidTls12TlsTestToolServerConfigForHashAlgo(String hashAlgo) {

    if (hashAlgo == null || hashAlgo.isBlank()) {
      throw new AssertionError("The Hash algorithm value is empty or null.");
    }

    var hash = TlsHashAlgorithm.fromDisplayName(hashAlgo);
    if (hash == TlsHashAlgorithm.UNKNOWN) {
      throw new AssertionError("The Hash algorithm value is unknown.");
    }

    LinkedHashSet<TlsHashAlgorithm> listOfHashes;
    if (hash == TlsHashAlgorithm.SUPPORTED_MIX) {
      listOfHashes = TlsHashAlgorithm.supportedByPolicy();
    } else {
      listOfHashes = new LinkedHashSet<>();
      listOfHashes.add(hash);
    }

    var tlsTestToolConfigBuffer = getTlsTestToolServerBaseConfig(TlsLibrary.OPENSSL)
        + "tlsSignatureAlgorithms=" + buildTls12SupportedSignatureHashPairs(listOfHashes) + "\n";

    runTlsTestToolServer(tlsTestToolConfigBuffer);
  }

  /**
   * Configures and runs TLS 1.2 for a readable cipher suite profile.
   *
   * @param profile cipher suite profile mapped to tls-test-tool tuple syntax
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für das Cipher-Suite-Profil {tlsCipherSuiteProfile}")
  @Given("the TLS 1.2 TlsTestTool server configuration data for the cipher suite profile {tlsCipherSuiteProfile}")
  public void setValidTls12TlsTestToolServerConfigForCipherSuiteProfile(TlsCipherSuite profile) {
    requireCipherSuiteProfileVersion(profile, TlsVersion.TLS_1_2);
    configureAndRunTls12ServerForCipherSuites(profile.getTlsTestToolCipherSuiteValue());
  }

  /**
   * Configures and runs TLS 1.3 for a readable cipher suite profile.
   *
   * @param profile cipher suite profile mapped to tls-test-tool tuple syntax
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für das Cipher-Suite-Profil {tlsCipherSuiteProfile}")
  @Given("the TLS 1.3 TlsTestTool server configuration data for the cipher suite profile {tlsCipherSuiteProfile}")
  public void setValidTls13TlsTestToolServerConfigForCipherSuiteProfile(TlsCipherSuite profile) {
    requireCipherSuiteProfileVersion(profile, TlsVersion.TLS_1_3);
    runTlsTestToolServer(buildTls13ServerConfig(profile.getTlsTestToolCipherSuiteValue()));
  }

  /**
   * Configures and runs TLS 1.2 for a supported cipher suite and a HelloRequest message.
   *
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten mit HelloRequest für eine der unterstützten Cipher-Suiten")
  @Given("the TLS 1.2 TlsTestTool server configuration data with HelloRequest support for a supported ciphersuite")
  public void setValidTls12TlsTestToolServerConfigHelloRequestForASupportedCipherSuite() {
    runTlsTestToolServer(
        buildTls12ServerConfig(
            buildSupportedCipherSuitesValue(TlsVersion.TLS_1_2),
            "manipulateRenegotiate="));
  }

  /**
   * Configures and runs TLS 1.2 for all supported cipher suites.
   *
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten")
  @Given("the TLS 1.2 TlsTestTool server configuration data for the supported ciphersuites")
  public void setValidTls12TlsTestToolServerConfigForAllSupportedCipherSuite() {
    runTlsTestToolServer(buildTls12ServerConfig(buildSupportedCipherSuitesValue(TlsVersion.TLS_1_2)));
  }

  /**
   * Configures and runs TLS 1.3 for all supported cipher suites.
   *
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten")
  @Given("the TLS 1.3 TlsTestTool server configuration data for the supported ciphersuites")
  public void setValidTls13TlsTestToolServerConfigForAllSupportedCipherSuite() {
    runTlsTestToolServer(buildTls13ServerConfigForSupportedCipherSuites());
  }

  /**
   * Configures and runs TLS 1.2 for all supported cipher suite profiles for a specific certificate.
   *
   * @param tlsServerCertificate certificate descriptor used for the server configuration
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit {tlsServerCertificate}")
  @Given("the TLS 1.2 TlsTestTool server configuration data for the supported ciphersuites for {tlsServerCertificate}")
  public void setValidTls12TlsTestToolServerConfigForACertificate(TlsServerCertificates tlsServerCertificate) {
    runTlsTestToolServer(
        buildTls12ServerConfig(
            buildSupportedCipherSuitesValue(TlsVersion.TLS_1_2),
            "manipulateForceCertificateUsage="),
        tlsServerCertificate);
  }

  /**
   * Configures and runs TLS 1.3 for all supported cipher suite profiles for a specific certificate.
   *
   * @param tlsServerCertificate certificate descriptor used for the server configuration
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit {tlsServerCertificate}")
  @Given("the TLS 1.3 TlsTestTool server configuration data for the supported ciphersuites for {tlsServerCertificate}")
  public void setValidTls13TlsTestToolServerConfigForACertificate(TlsServerCertificates tlsServerCertificate) {
    runTlsTestToolServer(buildTls13ServerConfigForSupportedCipherSuites(), tlsServerCertificate);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.2.
   *
   * @param host Host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für die optional unterstützten Cipher-Suiten")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for the optional ciphersuites")
  public void setTlsTestToolConfigForOptionalCipherSuite(String host) {
    // optional Cipher suites from [TR-02102-2], Chapter 3.3.1 Table 2
    // besides TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    var optionalTls12Ciphersuite = TlsCipherSuite.optionalTls12CipherSuites().stream().map(
        TlsCipherSuite::getTlsTestToolCipherSuiteValue).collect(Collectors.joining(","));
    var tlsCipherSuites = "tlsCipherSuites=" + optionalTls12Ciphersuite + "\n";
    runTls12TestTool(host, tlsCipherSuites);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.2.
   *
   * @param host Host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für die nicht unterstützten Cipher-Suiten")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for the unsupported ciphersuites")
  public void setTlsTestToolConfigForInvalidCipherSuite(String host) {
    // Cipher suites besides TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    // and those from [TR-02102-2], Chapter 3.3.1 Table 2
    var tlsCipherSuites = "tlsCipherSuites=(0x00,0x01),(0x00,0x02),(0x00,0x03),(0x00,0x04),"
        + "(0x00,0x05),(0x00,0x06),(0x00,0x17),(0x00,0x18),(0x00,0x20),(0x00,0x24),(0x00,0x27),"
        + "(0x00,0x28),(0x00,0x2a),(0x00,0x2b),(0x00,0x2c),(0x00,0x2d),(0x00,0x2e),(0x00,0x2f),"
        + "(0x00,0x30),(0x00,0x31),(0x00,0x32),(0x00,0x33),(0x00,0x34),(0x00,0x35),(0x00,0x36),"
        + "(0x00,0x37),(0x00,0x38),(0x00,0x39),(0x00,0x3a),(0x00,0x3b),(0x00,0x3c),(0x00,0x3d),"
        + "(0x00,0x3e),(0x00,0x41),(0x00,0x42),(0x00,0x43),(0x00,0x44),(0x00,0x45),(0x00,0x46),"
        + "(0x00,0x68),(0x00,0x6c),(0x00,0x6d),(0x00,0x84),(0x00,0x85),(0x00,0x86),(0x00,0x87),"
        + "(0x00,0x88),(0x00,0x89),(0x00,0x8a),(0x00,0x8c),(0x00,0x8d),(0x00,0x8e),(0x00,0x90),"
        + "(0x00,0x91),(0x00,0x92),(0x00,0x94),(0x00,0x95),(0x00,0x96),(0x00,0x97),(0x00,0x98),"
        + "(0x00,0x99),(0x00,0x9a),(0x00,0x9b),(0x00,0x9c),(0x00,0x9d),(0x00,0xa4),(0x00,0xa5),"
        + "(0x00,0xa9),(0x00,0xaa),(0x00,0xab),(0x00,0xac),(0x00,0xad),(0x00,0xae),(0x00,0xaf),"
        + "(0x00,0xb0),(0x00,0xb1),(0x00,0xb2),(0x00,0xb3),(0x00,0xb4),(0x00,0xb5),(0x00,0xb6),"
        + "(0x00,0xb7),(0x00,0xb8),(0x00,0xb9),(0x00,0xba),(0x00,0xbb),(0x00,0xbc),(0x00,0xbd),"
        + "(0x00,0xbe),(0x00,0xbf),(0x00,0xc0),(0x00,0xc1),(0x00,0xc2),(0x00,0xc3),(0x00,0xc4),"
        + "(0x00,0xc5),(0x00,0xff),(0xc0,0x01),(0xc0,0x02),(0xc0,0x04),(0xc0,0x05),(0xc0,0x22),"
        + "(0xc0,0x06),(0xc0,0x07),(0xc0,0x09),(0xc0,0x0a),(0xc0,0x0b),(0xc0,0x0c),(0xc0,0x0e),"
        + "(0xc0,0x0f),(0xc0,0x10),(0xc0,0x11),(0xc0,0x13),(0xc0,0x14),(0xc0,0x15),(0xc0,0x16),"
        + "(0xc0,0x18),(0xc0,0x19),(0xc0,0x1d),(0xc0,0x1e),(0xc0,0x1f),(0xc0,0x20),(0xc0,0x21),"
        + "(0xc0,0x2d),(0xc0,0x2e),(0xc0,0x33),(0xc0,0x35),(0xc0,0x36),(0xc0,0x37),(0xc0,0x38),"
        + "(0xc0,0x39),(0xc0,0x3a),(0xc0,0x3b),(0xc0,0x3c),(0xc0,0x3d),(0xc0,0x3e),(0xc0,0x3f),"
        + "(0xc0,0x40),(0xc0,0x41),(0xc0,0x42),(0xc0,0x43),(0xc0,0x44),(0xc0,0x45),(0xc0,0x46),"
        + "(0xc0,0x47),(0xc0,0x48),(0xc0,0x49),(0xc0,0x4a),(0xc0,0x4b),(0xc0,0x4c),(0xc0,0x4d),"
        + "(0xc0,0x4e),(0xc0,0x4f),(0xc0,0x50),(0xc0,0x51),(0xc0,0x52),(0xc0,0x53),(0xc0,0x54),"
        + "(0xc0,0x55),(0xc0,0x56),(0xc0,0x57),(0xc0,0x58),(0xc0,0x59),(0xc0,0x5a),(0xc0,0x5b),"
        + "(0xc0,0x5c),(0xc0,0x5d),(0xc0,0x5e),(0xc0,0x5f),(0xc0,0x60),(0xc0,0x61),(0xc0,0x62),"
        + "(0xc0,0x63),(0xc0,0x64),(0xc0,0x65),(0xc0,0x66),(0xc0,0x67),(0xc0,0x68),(0xc0,0x69),"
        + "(0xc0,0x6a),(0xc0,0x6b),(0xc0,0x6c),(0xc0,0x6d),(0xc0,0x6e),(0xc0,0x6f),(0xc0,0x70),"
        + "(0xc0,0x71),(0xc0,0x72),(0xc0,0x73),(0xc0,0x74),(0xc0,0x75),(0xc0,0x76),(0xc0,0x77),"
        + "(0xc0,0x78),(0xc0,0x79),(0xc0,0x7a),(0xc0,0x7b),(0xc0,0x7c),(0xc0,0x7d),(0xc0,0x7e),"
        + "(0xc0,0x7f),(0xc0,0x80),(0xc0,0x81),(0xc0,0x82),(0xc0,0x83),(0xc0,0x84),(0xc0,0x85),"
        + "(0xc0,0x86),(0xc0,0x87),(0xc0,0x88),(0xc0,0x89),(0xc0,0x8a),(0xc0,0x8b),(0xc0,0x8c),"
        + "(0xc0,0x8d),(0xc0,0x8e),(0xc0,0x8f),(0xc0,0x90),(0xc0,0x91),(0xc0,0x92),(0xc0,0x93),"
        + "(0xc0,0x94),(0xc0,0x95),(0xc0,0x96),(0xc0,0x97),(0xc0,0x98),(0xc0,0x99),(0xc0,0x9a),"
        + "(0xc0,0x9b),(0xc0,0x9c),(0xc0,0x9d),(0xc0,0xa0),(0xc0,0xa1),(0xc0,0xa2),(0xc0,0xa3),"
        + "(0xc0,0xa4),(0xc0,0xa5),(0xc0,0xa6),(0xc0,0xa7),(0xc0,0xa8),(0xc0,0xa9),(0xc0,0xaa),"
        + "(0xc0,0xab),(0xc0,0xae),(0xc0,0xaf),(0xcc,0xa8),(0xcc,0xa9),(0xc0,0x25),(0xc0,0x26),"
        + "(0xcc,0xaa),(0xcc,0xab),(0xcc,0xac),(0xcc,0xad),(0xcc,0xae),(0x00,0xa6),(0x00,0xa7),"
        + "(0x00,0xa8)\n";
    runTls12TestTool(host, tlsCipherSuites);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.2.
   *
   * @param host            Host to be tested
   * @param supportedGroups Hex value of the supported groups extension to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für die unterstützte Gruppe {string}")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for the supported groups {string}")
  public void setValidTlsTestToolConfigForSupportedGroups(String host, String supportedGroups) {
    if (supportedGroups == null || supportedGroups.isBlank()) {
      throw new AssertionError("The Supported Groups value is empty or null.");
    }
    runTls12SupportedGroupsScenario(host, supportedGroups);
  }

  /**
   * Configures and runs TLS 1.2 for a readable supported-groups profile.
   *
   * @param host    Host to be tested
   * @param supportedGroup supported-group
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für das unterstützte-Gruppen-Profil {string}")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for the supported-group profile {string}")
  public void setValidTlsTestToolConfigForSupportedGroupProfile(String host, String supportedGroup) {

    if (supportedGroup == null || supportedGroup.isBlank()) {
      throw new AssertionError("The Supported group value is empty or null.");
    }

    var group = TlsSupportedGroup.fromDisplayName(supportedGroup);

    if (group == TlsSupportedGroup.UNKNOWN) {
      throw new AssertionError("The Supported Group value is unknown.");
    }

    List<TlsSupportedGroup> listOfSupportedGroups;
    if (group == TlsSupportedGroup.UNSUPPORTED_MIX) {
      listOfSupportedGroups = TlsSupportedGroup.forbiddenGroups();
    } else {
      listOfSupportedGroups = List.of(group);
    }
    runTls12SupportedGroupsScenario(host, TlsSupportedGroup.buildSupportedGroupsExtension(listOfSupportedGroups));
  }

  /**
   * Configures and runs TLS 1.3 for a readable supported-groups profile.
   *
   * @param host Host to be tested
   * @param supportedGroup supported-group profile token
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für das unterstützte-Gruppen-Profil {string}")
  @Given("the TLS 1.3 TlsTestTool configuration data for the host {tigerResolvedString} for the supported-group profile {string}")
  public void setValidTls13TlsTestToolConfigForSupportedGroupProfile(String host, String supportedGroup) {

    if (supportedGroup == null || supportedGroup.isBlank()) {
      throw new AssertionError("The Supported group value is empty or null.");
    }

    var group = TlsSupportedGroup.fromDisplayName(supportedGroup);

    if (group == TlsSupportedGroup.UNKNOWN) {
      throw new AssertionError("The Supported Group value is unknown.");
    }

    List<TlsSupportedGroup> listOfSupportedGroups;
    if (group == TlsSupportedGroup.UNSUPPORTED_MIX) {
      listOfSupportedGroups = TlsSupportedGroup.forbiddenGroupsForTls13();
    } else {
      listOfSupportedGroups = List.of(group);
    }

    runTls13ClientScenario(
        host,
        getTls13TestValidCipherSuites(),
        TlsSignatureSchemes.recommendedSchemeNames(),
        TlsSignatureSchemes.recommendedSchemeHexValues(),
        TlsSupportedGroup.tls13SupportedGroupsValue(listOfSupportedGroups));
  }

  /**
   * Configures and runs TLS 1.2 for explicit {@code supported_groups} extension content.
   *
   * @param host            Host to be tested
   * @param supportedGroups Hex value of the supported groups extension to be tested
   */
  private void runTls12SupportedGroupsScenario(String host, String supportedGroups) {
    runTls12ClientScenario(
        host,
        getTls12TestValidEcdheCipherSuites(),
        SUPPORTED_SIGNATURE_HASH_ALGOS,
        supportedGroups,
        TlsHashAlgorithm.supportedByPolicy(),
        false);
  }

  /**
   * Configures and runs the TLS test tool for TLS 1.2. The TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) Cipher Suite is automatically added
   * by the TLS Test tool
   *
   * @param host Host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} für TLS Renegotiation")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} for TLS Renegotiation")
  public void setTlsTestToolConfigForRenegotiation(String host) {
    runTls12ClientScenario(
        host,
        getTls12TestValidCipherSuites(),
        SUPPORTED_SIGNATURE_HASH_ALGOS,
        VALID_SUPPORTED_GROUPS,
        TlsHashAlgorithm.supportedByPolicy(),
        true);
  }

  /**
   * Configures and runs TLS 1.2 with a semantically invalid RFC 5746
   * {@code renegotiation_info} extension in the initial ClientHello.
   *
   * <p>The extension is syntactically well-formed but advertises a non-empty
   * {@code renegotiated_connection} value during the initial handshake, which a compliant server
   * must reject.</p>
   *
   * @param host host to be tested
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit einer fehlerhaften renegotiation_info extension")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} with an invalid renegotiation_info extension")
  public void setTlsTestToolConfigWithInvalidRenegotiationInfoExtension(String host) {
    checkHost(host);

    var invalidRenegotiationInfoExtension = "ff0100020100";
    runTls12ClientScenario(
        host,
        getTls12TestValidCipherSuites(),
        invalidRenegotiationInfoExtension + SUPPORTED_SIGNATURE_HASH_ALGOS,
        VALID_SUPPORTED_GROUPS,
        TlsHashAlgorithm.supportedByPolicy(),
        false);
  }

  /**
   * Checks whether a Server Key exchange uses one of the supported hash functions.
   */
  @Dann("verwendet der Server-Schlüsselaustausch eine der unterstützten Hashfunktionen")
  @Then("the server key exchange uses one of the supported hash functions")
  public void checkIfTheServerKeyExchangeUsesOneOfTheSupportedHashFunctions() {
    requireTlsLogs();
    var matcher = TLS_HASH_ALGORITHM_PATTERN.matcher(tlsLogs);

    if (!matcher.find()) {
      if (tlsLogs != null && tlsLogs.contains("TLS handshake failed")) {
        throw new AssertionError(
            "The hash algorithm used for the Server Key exchange could not be found because the TLS handshake already failed. "
                + extractAlertSummary() + " " + buildHashNegotiationSummary());
      }
      throw new AssertionError("The hash algorithm used for the Server Key exchange could not be found. "
          + extractAlertSummary() + " " + buildHashNegotiationSummary());
    }
    var hashAlgorithmUsed = Integer.parseInt(matcher.group(1));
    var selectedHashAlgorithm = TlsHashAlgorithm.fromValue(hashAlgorithmUsed);
    if (selectedHashAlgorithm.isSupportedByPolicy()) {
      log.info("The {} hash algorithm was used for the Server Key exchange.", selectedHashAlgorithm);
      return;
    }
    throw new AssertionError("An unsupported hash algorithm with value " + hashAlgorithmUsed
        + " (" + selectedHashAlgorithm + ") was used for the Server Key exchange.");
  }

  /**
   * Checks whether the CertificateVerify message uses one of the supported hash functions.
   */
  @Dann("verwendet der Certificate-Verify eine der unterstützten Hashfunktionen")
  @Then("the certificate verify uses one of the supported hash functions")
  public void checkIfTheCertificateVerifyUsesOneOfTheSupportedHashFunctions() {
    requireTlsLogs();
    var matcher = TLS_CERTIFICATE_VERIFY_ALGORITHM_PATTERN.matcher(tlsLogs);

    if (!matcher.find()) {
      if (tlsLogs.contains("TLS handshake failed")) {
        throw new AssertionError(
            "The signature scheme used for CertificateVerify could not be found because the TLS handshake already failed. "
                + extractAlertSummary() + " " + buildHashNegotiationSummary());
      }
      throw new AssertionError("The signature scheme used for CertificateVerify could not be found. "
          + extractAlertSummary() + " " + buildHashNegotiationSummary());
    }

    var selectedScheme = TlsSignatureSchemes.fromAlgorithmBytes(matcher.group(1), matcher.group(2));
    var selectedHashAlgorithm = selectedScheme.getAssociatedHashAlgorithm();

    if (selectedHashAlgorithm != TlsHashAlgorithm.UNKNOWN && selectedHashAlgorithm.isSupportedByPolicy()) {
      log.info("The {} signature scheme using {} was used for CertificateVerify.", selectedScheme.getSchemeName(), selectedHashAlgorithm);
      return;
    }

    throw new AssertionError("An unsupported CertificateVerify signature scheme was used: "
        + selectedScheme.getSchemeName()
        + " "
        + selectedScheme.getHexValue()
        + " (hash="
        + selectedHashAlgorithm
        + ").");
  }

  /**
   * Checks whether the ServerHello key_share uses the expected supported-group profile.
   *
   * @param supportedGroup expected supported-group profile token
   */
  @Dann("ist das unterstützte-Gruppen-Profil {string} in der Server-Key-Share verwendet")
  @Then("the supported-group profile {string} is used in the server key share")
  public void checkIfTheServerKeyShareUsesSupportedGroupProfile(String supportedGroup) {
    requireTlsLogs();

    if (supportedGroup == null || supportedGroup.isBlank()) {
      throw new AssertionError("The Supported group value is empty or null.");
    }

    var expectedGroup = TlsSupportedGroup.fromDisplayName(supportedGroup);
    if (expectedGroup == TlsSupportedGroup.UNKNOWN || expectedGroup == TlsSupportedGroup.UNSUPPORTED_MIX) {
      throw new AssertionError("The Supported Group value is unknown or not singular.");
    }

    var serverHelloExtensions = extractHelloExtensions(tlsLogs, TlsEndpointRole.SERVER);
    var keyShare = findExtensionData(serverHelloExtensions, TLS_EXTENSION_KEY_SHARE);
    if (keyShare == null || keyShare.length < 2) {
      throw new AssertionError("The ServerHello key_share extension could not be found. " + extractAlertSummary());
    }

    var actualGroup = TlsSupportedGroup.fromValue(u16(keyShare, 0));
    Assertions.assertThat(actualGroup.getValue())
        .withFailMessage(
            "The ServerHello key_share used %s but expected %s for supported-group profile %s.",
            actualGroup.getDisplayName(),
            expectedGroup.getDisplayName(),
            supportedGroup)
        .isEqualTo(expectedGroup.getValue());
  }

  /**
   * Checks whether the server key exchange uses one of the supported curves.
   */
  @Dann("verwendet der Server-Schlüsselaustausch eine der unterstützten Kurven")
  @Then("the server key exchange uses one of the supported curves")
  public void checkIfTheServerKeyExchangeUsesOneOfTheSupportedCurves() {
    requireTlsLogs();
    var matcher = TLS_SERVER_KEY_EXCHANGE_NAMED_CURVE_PATTERN.matcher(tlsLogs);

    if (!matcher.find()) {
      throw new AssertionError(
          "The curve used for the Server Key exchange could not be found. " + extractAlertSummary());
    }

    var namedCurve = Integer.parseInt(matcher.group(1), 16);
    var selectedCurve = TlsSupportedGroup.fromValue(namedCurve);
    if (selectedCurve.getTls12Policy() == TlsSupportedGroup.Tls12Policy.MANDATORY
        || selectedCurve.getTls12Policy() == TlsSupportedGroup.Tls12Policy.OPTIONAL) {
      log.info("The {} curve was used for the Server Key exchange.", selectedCurve.getDisplayName());
      return;
    }

    throw new AssertionError("An unsupported curve with value " + namedCurve
        + " (" + selectedCurve.getDisplayName() + ") was used for the Server Key exchange.");
  }

  /**
   * Configures and runs the TLS test tool for hash functions < SHA-256.
   *
   * @param host          Host to be tested
   * @param hashFunctions Hash algorithms that must not be supported
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden nicht unterstützten Hashfunktionen wurden festgelegt:")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} has been set using the following unsupported hash functions:")
  public void setTls12TlsTestToolConfigForInvalidHash(String host, DataTable hashFunctions) {
    checkHost(host);
    if (hashFunctions == null) {
      throw new AssertionError("The hash functions table is null.");
    }

    // Check if all supported TLS 1.2 hash algorithms are present.
    var hashFunctionsHashSet = parseNonEmptyFirstColumn(hashFunctions, LinkedHashSet::new);

    var unsupportedHashFunctions = TlsHashAlgorithm.unsupportedByPolicyNames();

    if (!unsupportedHashFunctions.equals(hashFunctionsHashSet)) {
      throw new AssertionError("""
          For this test, the signature hash algorithms cannot be changed.
          They must be:
          - MD5
          - SHA1
          - SHA224""");
    }
    lastOfferedTlsHashAlgorithms = mapNamesToHashAlgorithms(hashFunctionsHashSet);

    runTls12ClientScenario(
        host,
        getTls12TestValidCipherSuites(),
        UNSUPPORTED_SIGNATURE_HASH_ALGOS,
        VALID_SUPPORTED_GROUPS,
        TlsHashAlgorithm.unsupportedByPolicy(),
        false);

  }

  /**
   * Configures and runs the TLS test tool for supported hash algorithms.
   *
   * @param host          Host to be tested
   * @param hashFunctions Hash algorithms that are supported
   */
  @Gegebensei("die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden unterstützten Hashfunktionen wurden festgelegt:")
  @Given("the TLS 1.2 TlsTestTool configuration data for the host {tigerResolvedString} has been set with the following supported hash functions:")
  public void setTls12TlsTestToolConfigForValidHash(String host, DataTable hashFunctions) {
    checkHost(host);
    if (hashFunctions == null) {
      throw new AssertionError("The hash functions table is null.");
    }

    // Check if all the supported/mandatory SignatureAndHashAlgorithms are present
    var hashFunctionsHashSet = parseNonEmptyFirstColumn(hashFunctions, LinkedHashSet::new);

    var supportedHashFunctions = TlsHashAlgorithm.supportedByPolicyNames();

    if (!supportedHashFunctions.equals(hashFunctionsHashSet)) {
      throw new AssertionError("""
          For this test, the signature hash algorithms cannot be changed.
          They must be:
          - SHA256
          - SHA384
          - SHA512""");
    }
    lastOfferedTlsHashAlgorithms = mapNamesToHashAlgorithms(hashFunctionsHashSet);

    runTls12ClientScenario(
        host,
        getTls12TestValidCipherSuites(),
        SUPPORTED_SIGNATURE_HASH_ALGOS,
        VALID_SUPPORTED_GROUPS,
        TlsHashAlgorithm.supportedByPolicy(),
        false);

  }

  /**
   * Configures and runs the TLS test tool for supported hash algorithms.
   *
   * @param host          Host to be tested
   * @param hashFunctions Hash algorithms that are supported
   */
  @Gegebensei("die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host {tigerResolvedString} mit den folgenden unterstützten Hashfunktionen wurden festgelegt:")
  @Given("the TLS 1.3 TlsTestTool configuration data for the host {tigerResolvedString} has been set with the following supported hash functions:")
  public void setTls13TlsTestToolConfigForValidHash(String host, DataTable hashFunctions) {
    checkHost(host);
    if (hashFunctions == null) {
      throw new AssertionError("The hash functions table is null.");
    }

    // Check if all the supported/mandatory SignatureAndHashAlgorithms are present
    var hashFunctionsHashSet = parseNonEmptyFirstColumn(hashFunctions, LinkedHashSet::new);

    var supportedHashFunctions = TlsHashAlgorithm.supportedByPolicyNames();

    if (!supportedHashFunctions.equals(hashFunctionsHashSet)) {
      throw new AssertionError("""
          For this test, the signature hash algorithms cannot be changed.
          They must be:
          - SHA256
          - SHA384
          - SHA512""");
    }
    lastOfferedTlsHashAlgorithms = mapNamesToHashAlgorithms(hashFunctionsHashSet);
    var supportedHashes = mapNamesToHashAlgorithms(hashFunctionsHashSet);

    runTls13ClientScenario(
        host,
        getTls13TestValidCipherSuites(),
        TlsSignatureSchemes.recommendedSchemeNamesForHashes(supportedHashes),
        TlsSignatureSchemes.recommendedSchemeHexValuesForHashes(supportedHashes),
        TlsSupportedGroup.tls13SupportedGroups());

  }

  /**
   * Resolves a readable handshake expectation token from a feature file.
   *
   * @param expectation textual expectation token
   * @return matching handshake expectation enum
   */
  @ParameterType("erfolgreich|nicht erfolgreich|successful|not successful")
  public TlsHandshakeExpectation tlsHandshakeExpectation(String expectation) {
    return TlsHandshakeExpectation.fromValue(expectation);
  }

  /**
   * Checks whether the TLS handshake matches the expected result.
   */
  @Dann("ist der TLS-Handshake {tlsHandshakeExpectation}")
  @Then("the TLS handshake is {tlsHandshakeExpectation}")
  public void checkIfTlsHandshakeMatchesExpectation(TlsHandshakeExpectation expectation) {
    if (expectation == null) {
      throw new AssertionError("The TLS handshake expectation is empty or null.");
    }
    switch (expectation) {
      case ERFOLGREICH -> checkForMessageInTlsLogs("Handshake successful");
      case NICHT_ERFOLGREICH -> checkForMessageInTlsLogs("TLS handshake failed", "Handshake aborted");
      default -> throw new AssertionError("Unsupported TLS handshake expectation: " + expectation);
    }
  }

  /**
   * Checks whether the TLS test tool established the TCP/IP connection before the TLS handshake.
   */
  @Dann("die TCP-IP-Verbindung wird hergestellt")
  @Then("the TCP-IP connection is established")
  public void checkTcpIpConnectionIsEstablished() {
    requireTlsLogs();

    Assertions
        .assertThat(TCP_IP_CONNECTION_ESTABLISHED_PATTERN.matcher(tlsLogs).find())
        .withFailMessage(
            "The TCP/IP connection was not established. %s",
            extractTcpIpConnectionSummary(tlsLogs))
        .isTrue();
  }

  /**
   * Checks whether the ClientHello only offers the supported curves.
   */
  @Dann("bietet der ClientHello nur die unterstützten Kurven an")
  @Then("the client hello only offers the supported curves")
  public void checkClientHelloForSupportedCurves() {
    var allowedSet = new HashSet<>(TlsSupportedGroup.allowedGroups());
    assertOnlyAllowedValues(
        extractSupportedGroupsHex(tlsLogs),
        allowedSet::contains,
        "No supported_groups extension entries found in ClientHello logs.",
        "The following un-supported Supported Groups were advertised by the Client. %s");
  }

  /**
   * Checks whether the ClientHello key_share only uses supported curves.
   */
  @Dann("ist einer die unterstützten Kurven ist in der Client-Key-Share verwendet")
  @Then("only the supported curves are used in the client key share")
  public void checkClientKeyShareForSupportedCurvesOnly() {
    requireTlsLogs();
    var allowedSet = new HashSet<>(TlsSupportedGroup.allowedGroups());
    assertOnlyAllowedValues(
        extractClientKeyShareGroups(tlsLogs),
        allowedSet::contains,
        "No key_share extension entries found in ClientHello logs.",
        "The following unsupported Supported Groups were used in ClientHello.key_share. %s");
  }

  /**
   * Checks whether the ClientHello only offers supported TLS-1.3 signature schemes.
   */
  @Dann("bietet der ClientHello nur die unterstützten Signature-Schemes an")
  @Then("the client hello only offers the supported signature schemes")
  public void checkClientHelloForSupportedTls13SignatureSchemes() {
    requireTlsLogs();
    assertOnlyAllowedValues(
        extractTls13SignatureSchemes(tlsLogs),
        scheme -> scheme.getTls13Policy() == TlsSignatureSchemes.Tls13Policy.RECOMMENDED,
        "No TLS 1.3 signature schemes found in ClientHello logs.",
        "The following unsupported TLS 1.3 Signature Schemes were advertised by the Client. %s");
  }

  /**
   * Checks whether the ClientHello does not offer any unsupported RSA TLS 1.3 signature schemes.
   */
  @Dann("bietet der ClientHello keine nicht unterstützten RSA TLS 1.3 Signature-Schemes an")
  @Then("the client hello does not offer any unsupported RSA TLS 1.3 signature schemes")
  public void checkClientHelloForNoUnsupportedRsaTls13SignatureSchemes() {
    requireTlsLogs();
    var unsupportedSet = new HashSet<>(TlsSignatureSchemes.unsupportedRsaSchemes());
    assertOnlyAllowedValues(
        extractTls13SignatureSchemes(tlsLogs),
        scheme -> !unsupportedSet.contains(scheme),
        "No TLS 1.3 RSA signature schemes found in ClientHello logs.",
        "The following unsupported TLS RSA 1.3 Signature Schemes were advertised by the Client. %s");
  }

  /**
   * Checks whether the ClientHello does not offer any unsupported TLS 1.3 signature schemes.
   */
  @Dann("bietet der ClientHello keine nicht unterstützten TLS 1.3 Signature-Schemes an")
  @Then("the client hello does not offer any unsupported TLS 1.3 signature schemes")
  public void checkClientHelloForNoUnsupportedTls13SignatureSchemes() {
    requireTlsLogs();
    var unsupportedSet = new HashSet<>(TlsSignatureSchemes.unsupportedSchemes());
    assertOnlyAllowedValues(
        extractTls13SignatureSchemes(tlsLogs),
        scheme -> !unsupportedSet.contains(scheme),
        "No TLS 1.3 signature schemes found in ClientHello logs.",
        "The following unsupported TLS 1.3 Signature Schemes were advertised by the Client. %s");
  }

  /**
   * Checks whether the ClientHello does not offer any unsupported signature algorithms.
   */
  @Dann("bietet der ClientHello keine nicht unterstützten Signaturalgorithmen an")
  @Then("the client hello does not offer any unsupported signature algorithms")
  public void checkClientHelloForNoUnsupportedSignatureAlgorithms() {
    Set<TlsSignatureAlgorithm> unsupportedSet = new HashSet<>(TlsSignatureAlgorithm.getUnsupportedSignatureAlgorithms());
    assertOnlyAllowedValues(
        extractSignatureAlgorithmsHex(tlsLogs),
        signatureAlgorithm -> !unsupportedSet.contains(signatureAlgorithm),
        "No signature_algorithms entries found in ClientHello logs.",
        "The following unsupported Signature Algorithms were advertised by the Client. %s");
  }

  /**
   * Checks whether the TLS test tool logs contain the transmitted Certificate message.
   */
  @Dann("wurde die TLS-Certificate übertragen")
  @Then("the TLS Certificate was transmitted")
  public void checkCertificateWasTransmitted() {
    requireTlsLogs();
    var expectedMessage = "Certificate message transmitted.";
    Assertions
        .assertThat(tlsLogs.contains(expectedMessage))
        .withFailMessage(
            "The TLS Certificate message was not transmitted. This failure is not caused by the test scenario assertion; "
                + "the TLS handshake broke earlier for another reason. %s",
            extractAlertSummary())
        .isTrue();
  }

  /**
   * Checks whether the handshake renegotiation is initiated.
   */
  @Dann("wird die TLS-Handshake-renegotiation gestartet")
  @Then("the TLS handshake renegotiation is triggered")
  public void checkIfTlsRenegotiationIsTriggered() {
    checkForMessageInTlsLogs("Performing renegotiation");
  }

  /**
   * Checks whether the handshake renegotiation was successful.
   */
  @Dann("ist die TLS-Handshake-renegotiation erfolgreich")
  @Then("the TLS handshake renegotiation is successful")
  public void checkIfTlsRenegotiationIsSuccessful() {
    checkForMessageInTlsLogs("<= handshake");

    // If a renegotiation is successful, then the "<= renegotiate" message is logged
    checkForMessageInTlsLogs("<= renegotiate");
  }

  /**
   * Checks whether the handshake renegotiation was explicitly refused with the expected TLS alert.
   *
   * @param descriptionId expected TLS alert description in hexadecimal form without {@code 0x} prefix
   */
  @Dann("die TLS-Handshake-renegotiation wird mit einer Alert Nachricht mit Description Id {string} abgelehnt")
  @Then("the TLS handshake renegotiation is rejected with an alert message having description id {string}")
  public void checkIfTlsRenegotiationIsRejectedWithAlertDescription(String descriptionId) {
    requireTlsLogs();

    Assertions
        .assertThat(TLS_RENEGOTIATION_PHASE_PATTERN.matcher(tlsLogs).find())
        .withFailMessage("No TLS renegotiation phase was found in the TLS logs.")
        .isTrue();

    var renegotiationPhase = extractRelevantLogPhase();

    Assertions
        .assertThat(renegotiationPhase)
        .withFailMessage(
            "Alert.description=%s not found in renegotiation phase. %s",
            descriptionId,
            extractAlertSummary())
        .contains("Alert.description=" + descriptionId);

    Assertions
        .assertThat(renegotiationPhase)
        .withFailMessage(
            "TLS renegotiation failure marker not found in renegotiation phase. %s",
            extractAlertSummary())
        .contains("TLS handshake failed");

    Assertions
        .assertThat(hasFinishedAfterRenegotiation(tlsLogs))
        .withFailMessage("Renegotiation completed successfully although rejection was expected.")
        .isFalse();
  }

  /**
   * Checks whether TLS renegotiation is handled in an RFC 5746 compliant way.
   *
   * <p>A peer is compliant if it either completes secure renegotiation successfully or rejects
   * renegotiation with a fatal {@code no_renegotiation} alert (description id {@code 64}) or
   * a fatal {@code handshake_failure} alert (description id {@code 28}).</p>
   */
  @Dann("ist die TLS-Handshake-renegotiation RFC-5746-konform erfolgreich oder wird mit no_renegotiation oder handshake_failure abgelehnt")
  @Then("the TLS handshake renegotiation is RFC 5746 compliant by succeeding or being rejected with no_renegotiation or handshake_failure")
  public void checkIfTlsRenegotiationIsRfc5746Compliant() {
    requireTlsLogs();

    if (hasFinishedAfterRenegotiation(tlsLogs)) {
      assertSecureRenegotiationBinding(tlsLogs);
      return;
    }

    var renegotiationPhase = extractRelevantLogPhase();

    if (renegotiationPhase.isBlank()) {
      throw new AssertionError("The TLS renegotiation log is empty or null.");
    }

    Assertions
        .assertThat(hasAlertLevel(renegotiationPhase, "02"))
        .withFailMessage(
            "Renegotiation neither completed successfully nor was it rejected with fatal Alert.level=02. %s",
            extractAlertSummary())
        .isTrue();

    Assertions
        .assertThat(hasAlertDescription(renegotiationPhase, "64") || hasAlertDescription(renegotiationPhase, "28"))
        .withFailMessage(
            "Renegotiation neither completed successfully nor was it rejected with Alert.description=64 or Alert.description=28. %s",
            extractAlertSummary())
        .isTrue();

    Assertions
            .assertThat(
                hasFatalAlertDescription(renegotiationPhase, "64")
                    || hasFatalAlertDescription(renegotiationPhase, "28"))
           .withFailMessage(
                "Renegotiation neither completed successfully nor was the alert level and description not paired as fatal Alert.description=64 or fatal Alert.description=28. %s",
                extractAlertSummary())
            .isTrue();
  }

  /**
   * Checks whether a TLS log phase contains the given alert description paired with a fatal alert level.
   *
   * @param logPhase TLS log phase to inspect
   * @param descriptionId expected alert description id
   * @return {@code true} if the description appears after {@code Alert.level=02}
   */
  private static boolean hasFatalAlertDescription(String logPhase, String descriptionId) {
    var currentAlertLevel = (String) null;
    for (var line : logPhase.split("\\R")) {
      var levelMatcher = ALERT_LEVEL_PATTERN.matcher(line);
      if (levelMatcher.find()) {
        currentAlertLevel = levelMatcher.group(1);
      }
      var descriptionMatcher = ALERT_DESCRIPTION_PATTERN.matcher(line);
      if (descriptionMatcher.find() && descriptionId.equalsIgnoreCase(descriptionMatcher.group(1))) {
        return "02".equals(currentAlertLevel);
      }
    }
    return false;
  }

  /**
   * Checks whether a TLS log phase contains the given alert level.
   *
   * @param logPhase TLS log phase to inspect
   * @param levelId expected alert level id
   * @return {@code true} if the level is present
   */
  private static boolean hasAlertLevel(String logPhase, String levelId) {
    return ALERT_LEVEL_PATTERN.matcher(logPhase).results()
        .anyMatch(match -> levelId.equalsIgnoreCase(match.group(1)));
  }

  /**
   * Checks whether a TLS log phase contains the given alert description.
   *
   * @param logPhase TLS log phase to inspect
   * @param descriptionId expected alert description id
   * @return {@code true} if the description is present
   */
  private static boolean hasAlertDescription(String logPhase, String descriptionId) {
    return ALERT_DESCRIPTION_PATTERN.matcher(logPhase).results()
        .anyMatch(match -> descriptionId.equalsIgnoreCase(match.group(1)));
  }

  /**
   * Validates that a successful renegotiation binds the new handshake to the previous Finished
   * verify_data values as required by RFC 5746.
   *
   * @param fullLog complete TLS log output
   */
  private static void assertSecureRenegotiationBinding(String fullLog) {
    if (fullLog == null || fullLog.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }

    int renegotiationIndex = fullLog.indexOf(RENEG_MARKER);
    if (renegotiationIndex < 0) {
      throw new AssertionError("No TLS renegotiation phase was found in the TLS logs.");
    }

    var initialHandshakePhase = fullLog.substring(0, renegotiationIndex);
    var renegotiationPhase = fullLog.substring(renegotiationIndex);
    var tlsTestToolRole = determineTlsTestToolRole(fullLog);

    var previousClientFinished = extractFinishedVerifyData(initialHandshakePhase, tlsTestToolRole, TlsEndpointRole.CLIENT);
    var previousServerFinished = extractFinishedVerifyData(initialHandshakePhase, tlsTestToolRole, TlsEndpointRole.SERVER);

    var renegotiatedClientHelloExtensions = extractHelloExtensions(renegotiationPhase, TlsEndpointRole.CLIENT);
    var renegotiatedServerHelloExtensions = extractHelloExtensions(renegotiationPhase, TlsEndpointRole.SERVER);

    var actualClientRenegotiationInfo = findExtensionData(renegotiatedClientHelloExtensions, TLS_EXTENSION_RENEGOTIATION_INFO);
    var expectedClientRenegotiationInfo = buildRenegotiationInfoPayload(previousClientFinished);
    Assertions
        .assertThat(actualClientRenegotiationInfo)
        .withFailMessage(
            "The renegotiated ClientHello renegotiation_info is missing or malformed. Expected %s but found %s.",
            toHex(expectedClientRenegotiationInfo),
            toHex(actualClientRenegotiationInfo))
        .isEqualTo(expectedClientRenegotiationInfo);

    var actualServerRenegotiationInfo = findExtensionData(renegotiatedServerHelloExtensions, TLS_EXTENSION_RENEGOTIATION_INFO);
    var expectedServerRenegotiationInfo =
        buildRenegotiationInfoPayload(previousClientFinished, previousServerFinished);
    Assertions
        .assertThat(actualServerRenegotiationInfo)
        .withFailMessage(
            "The renegotiated ServerHello renegotiation_info is missing or malformed. Expected %s but found %s.",
            toHex(expectedServerRenegotiationInfo),
            toHex(actualServerRenegotiationInfo))
        .isEqualTo(expectedServerRenegotiationInfo);
  }

  /**
   * Determines whether the TLS test tool acts as TLS client or TLS server in the current log.
   *
   * @param fullLog complete TLS log output
   * @return detected TLS test tool endpoint role
   */
  private static TlsEndpointRole determineTlsTestToolRole(String fullLog) {
    int transmittedClientHelloIndex = fullLog.indexOf("ClientHello message transmitted.");
    int receivedClientHelloIndex = fullLog.indexOf("Valid ClientHello message received.");

    if (transmittedClientHelloIndex >= 0
        && (receivedClientHelloIndex < 0 || transmittedClientHelloIndex < receivedClientHelloIndex)) {
      return TlsEndpointRole.CLIENT;
    }
    if (receivedClientHelloIndex >= 0) {
      return TlsEndpointRole.SERVER;
    }

    throw new AssertionError("Unable to determine whether the TLS test tool acted as client or server.");
  }

  /**
   * Extracts the verify_data bytes of the requested Finished message from the given handshake phase.
   *
   * @param handshakePhase TLS log excerpt containing exactly one completed handshake phase
   * @param tlsTestToolRole TLS endpoint role of the TLS test tool
   * @param finishedSenderRole TLS endpoint role whose Finished verify_data should be extracted
   * @return Finished verify_data bytes
   */
  private static byte[] extractFinishedVerifyData(
      String handshakePhase,
      TlsEndpointRole tlsTestToolRole,
      TlsEndpointRole finishedSenderRole) {
    var finishedMarker =
        tlsTestToolRole == finishedSenderRole
            ? "Finished message transmitted."
            : "Valid Finished message received.";
    var finishedDataPattern =
        Pattern.compile("tlsHandshakeMessage type\\s*=\\s*0x14 data\\s*=\\s*([0-9a-fA-F ]+)");

    byte[] lastFinishedData = null;
    for (var line : handshakePhase.split("\\R")) {
      var matcher = finishedDataPattern.matcher(line);
      if (matcher.find()) {
        lastFinishedData = parseHexBytes(matcher.group(1));
      }

      if (line.contains(finishedMarker)) {
        if (lastFinishedData == null) {
          throw new AssertionError("Finished verify_data could not be extracted before '" + finishedMarker + "'.");
        }
        return lastFinishedData;
      }
    }

    throw new AssertionError("No '" + finishedMarker + "' entry was found before renegotiation.");
  }

  /**
   * Extracts the extension block bytes for the first ClientHello or ServerHello in the given phase.
   *
   * @param handshakePhase TLS log excerpt for one handshake phase
   * @param helloRole selects ClientHello or ServerHello
   * @return parsed extension block bytes
   */
  private static byte[] extractHelloExtensions(String handshakePhase, TlsEndpointRole helloRole) {
    var pattern =
        helloRole == TlsEndpointRole.CLIENT
            ? CLIENT_HELLO_EXTENSIONS_OPTIONAL_PATTERN
            : SERVER_HELLO_EXTENSIONS_PATTERN;
    var matcher = pattern.matcher(handshakePhase);
    if (!matcher.find() || matcher.group(1) == null || matcher.group(1).isBlank()) {
      throw new AssertionError("No " + helloRole.getDisplayName() + " hello extensions were found in the TLS logs.");
    }
    return parseHexBytes(matcher.group(1));
  }

  /**
   * Extracts the raw TLS extensions block matched by the given pattern.
   *
   * @param fullLog complete TLS test tool log output
   * @param extensionsPattern pattern matching a hello extensions line
   * @param failIfMissing whether a missing extensions line should raise an assertion
   * @return parsed extension bytes, or an empty array if the matched block is blank or malformed
   * @throws AssertionError if {@code fullLog} is {@code null/blank}, or if the extensions line is missing
   *                        and {@code failIfMissing} is {@code true}
   */
  private static byte[] extractHelloExtensions(String fullLog, Pattern extensionsPattern, boolean failIfMissing) {
    if (fullLog == null || fullLog.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }

    Matcher matcher = extensionsPattern.matcher(fullLog);
    if (!matcher.find()) {
      if (failIfMissing) {
        throw new AssertionError("Client hello extension not present in the logs.");
      }
      return new byte[0];
    }

    String extensionBytes = matcher.group(1);
    if (extensionBytes == null || extensionBytes.isBlank()) {
      return new byte[0];
    }

    try {
      return parseHexBytes(extensionBytes);
    } catch (NumberFormatException e) {
      return new byte[0];
    }
  }

  /**
   * Builds the RFC 5746 renegotiation_info payload including its vector-length octet.
   *
   * @param verifyDataParts verify_data fragments that must be concatenated
   * @return encoded renegotiation_info payload
   */
  private static byte[] buildRenegotiationInfoPayload(byte[]... verifyDataParts) {
    int payloadLength = 0;
    for (var verifyDataPart : verifyDataParts) {
      if (verifyDataPart != null) {
        payloadLength += verifyDataPart.length;
      }
    }

    if (payloadLength > 0xFF) {
      throw new AssertionError("renegotiation_info payload exceeds the supported length encoding.");
    }

    var renegotiationInfo = new byte[payloadLength + 1];
    renegotiationInfo[0] = (byte) payloadLength;

    int offset = 1;
    for (var verifyDataPart : verifyDataParts) {
      if (verifyDataPart == null || verifyDataPart.length == 0) {
        continue;
      }
      System.arraycopy(verifyDataPart, 0, renegotiationInfo, offset, verifyDataPart.length);
      offset += verifyDataPart.length;
    }

    return renegotiationInfo;
  }

  /**
   * Formats a byte array as lowercase hex pairs separated by blanks.
   *
   * @param bytes bytes to format
   * @return human-readable hex dump or {@code "null"}
   */
  private static String toHex(byte[] bytes) {
    if (bytes == null) {
      return "null";
    }
    return Hex.encodeHexString(bytes).replaceAll("..(?!$)", "$0 ").trim();
  }

  /**
   * Checks whether the server initiated renegotiation was successful.
   */
  @Dann("ist die TLS-Server initiierte renegotiation erfolgreich")
  @Then("the TLS Server initiated renegotiation is successful")
  public void checkIfTlsServerInitiatedRenegotiationIsSuccessful() {
    Assertions
        .assertThat(hasFinishedAfterRenegotiation(tlsLogs))
        .withFailMessage("Server-initiated renegotiation was not completed successfully.")
        .isTrue();
  }

  /**
   * Checks whether the specified message is present in the TLS logs.
   *
   * @param message message to search for in TLS logs
   * @param optionalMessages optional alternative messages; if present, at least one expected message must appear
   */
  private void checkForMessageInTlsLogs(String message, String... optionalMessages) {
    requireTlsLogs();

    var expectedMessages = new ArrayList<String>();
    if (message != null && !message.isBlank()) {
      expectedMessages.add(message);
    }
    if (optionalMessages != null) {
      for (var optionalMessage : optionalMessages) {
        if (optionalMessage != null && !optionalMessage.isBlank()) {
          expectedMessages.add(optionalMessage);
        }
      }
    }
    if (expectedMessages.isEmpty()) {
      throw new AssertionError("No valid message to search for in TLS logs.");
    }
    var containsAnyExpectedMessage = expectedMessages.stream().anyMatch(tlsLogs::contains);

    Assertions
        .assertThat(containsAnyExpectedMessage)
        .withFailMessage(
            "None of the expected messages %s were found in TLS logs. %s %s",
            expectedMessages,
            extractAlertSummary(),
            buildHashNegotiationSummary())
        .isTrue();
  }

  /**
   * Extracts a compact TCP/IP connection diagnostic from raw TLS tool logs.
   *
   * @param fullLog complete TLS log output
   * @return connection diagnostic for assertion messages
   */
  private static String extractTcpIpConnectionSummary(String fullLog) {
    if (fullLog == null || fullLog.isBlank()) {
      return "TLS logs are empty.";
    }
    var failedConnectionMatcher = TCP_IP_CONNECTION_FAILED_PATTERN.matcher(fullLog);
    if (failedConnectionMatcher.find()) {
      return "connection_failure=" + failedConnectionMatcher.group(0).trim();
    }
    return "No TCP/IP connection status line was found.";
  }

  /**
   * Extract a compact alert summary from raw TLS tool logs to improve failure readability.
   *
   * @return compact summary with alert details and relevant handshake metadata
   */
  private String extractAlertSummary() {
    if (tlsLogs == null || tlsLogs.isBlank()) {
      return "TLS logs are empty.";
    }
    var lines = Arrays.stream(tlsLogs.split("\\R")).toList();
    var relevantPhase = determineRelevantLogPhase(lines);
    var level = (String) null;
    var description = (String) null;
    var handshakeFailure = (String) null;
    var selectedCipherSuite = (String) null;
    var selectedHash = (TlsHashAlgorithm) null;
    var selectedSignature = (TlsSignatureAlgorithm) null;
    var selectedTls13SignatureScheme = (String) null;
    var selectedServerKeyShare = (String) null;
    var handshakeSuccessful = false;
    var lastLine = (String) null;

    for (var line : lines.subList(relevantPhase.startInclusive(), relevantPhase.endExclusive())) {
      var trimmedLine = line.trim();
      if (!trimmedLine.isEmpty()) {
        lastLine = trimmedLine;
        if (trimmedLine.contains("Handshake successful.")) {
          handshakeSuccessful = true;
        }
      }
      var levelMatcher = ALERT_LEVEL_PATTERN.matcher(line);
      if (levelMatcher.find()) {
        level = levelMatcher.group(1);
      }
      var descriptionMatcher = ALERT_DESCRIPTION_PATTERN.matcher(line);
      if (descriptionMatcher.find()) {
        description = descriptionMatcher.group(1);
      }
      var handshakeFailureMatcher = TLS_HANDSHAKE_FAILED_PATTERN.matcher(line);
      if (handshakeFailureMatcher.find()) {
        handshakeFailure = handshakeFailureMatcher.group(0);
      }
      var selectedCipherSuiteMatcher = TLS_CIPHER_SUITE_PATTERN.matcher(line);
      if (selectedCipherSuiteMatcher.find()) {
        selectedCipherSuite = selectedCipherSuiteMatcher.group(1).trim();
      }
      var serverHelloCipherSuiteMatcher = TLS_SERVER_HELLO_CIPHER_SUITE_PATTERN.matcher(line);
      if (serverHelloCipherSuiteMatcher.find()) {
        selectedCipherSuite =
            formatTlsCipherSuite(serverHelloCipherSuiteMatcher.group(1), serverHelloCipherSuiteMatcher.group(2));
      }
      var selectedHashMatcher = TLS_HASH_ALGORITHM_PATTERN.matcher(line);
      if (selectedHashMatcher.find()) {
        selectedHash = TlsHashAlgorithm.fromValue(Integer.parseInt(selectedHashMatcher.group(1)));
      }
      var selectedSignatureMatcher = TLS_SIGNATURE_ALGORITHM_PATTERN.matcher(line);
      if (selectedSignatureMatcher.find()) {
        selectedSignature = TlsSignatureAlgorithm.fromValue(Integer.parseInt(selectedSignatureMatcher.group(1)));
      }
      var certificateVerifyMatcher = TLS_CERTIFICATE_VERIFY_ALGORITHM_PATTERN.matcher(line);
      if (certificateVerifyMatcher.find()) {
        selectedTls13SignatureScheme =
            formatTls13SignatureScheme(certificateVerifyMatcher.group(1), certificateVerifyMatcher.group(2));
      }
      var serverKeyShareMatcher = TLS_SERVER_HELLO_KEY_SHARE_GROUP_PATTERN.matcher(line);
      if (serverKeyShareMatcher.find()) {
        selectedServerKeyShare =
            formatTlsSupportedGroup(serverKeyShareMatcher.group(1), serverKeyShareMatcher.group(2));
      }
    }

    var summary = new StringBuilder();
    summary.append("Alert summary:");
    summary.append(" level=").append(level != null ? level : "n/a");
    summary.append(", description=").append(description != null ? description : "n/a");
    if (handshakeFailure != null) {
      summary.append(", ").append(handshakeFailure);
    } else if (lastLine != null) {
      summary.append(", last_log_line=").append(lastLine);
    }
    if (handshakeSuccessful) {
      summary.append(", handshake_successful=true");
    }
    if (selectedCipherSuite != null) {
      summary.append(", selected_cipher_suite=").append(selectedCipherSuite);
    }
    if (selectedTls13SignatureScheme != null) {
      summary.append(", selected_tls13_signature_scheme=").append(selectedTls13SignatureScheme);
    }
    if (selectedServerKeyShare != null) {
      summary.append(", selected_server_key_share=").append(selectedServerKeyShare);
    }
    if (selectedHash != null) {
      summary.append(", selected_hash=")
          .append(selectedHash.name())
          .append("(")
          .append(selectedHash.getValue())
          .append("/")
          .append(selectedHash.getHexValue())
          .append(")");
    }
    if (selectedSignature != null) {
      summary.append(", selected_signature=")
          .append(selectedSignature.name())
          .append("(")
          .append(selectedSignature.getValue())
          .append("/")
          .append(selectedSignature.getHexValue())
          .append(")");
    }
    return summary.toString();
  }

  /**
   * Formats a TLS cipher-suite byte pair as a readable cipher-suite name.
   *
   * @param firstByte first logged cipher-suite byte
   * @param secondByte second logged cipher-suite byte
   * @return matching cipher-suite name, or a raw unknown marker
   */
  private static String formatTlsCipherSuite(String firstByte, String secondByte) {
    var tuple = formatHexBytePair(firstByte, secondByte);
    return Arrays.stream(TlsCipherSuite.values())
        .filter(cipherSuite -> cipherSuite.getTlsTestToolCipherSuiteValue().equalsIgnoreCase(tuple))
        .findFirst()
        .map(TlsCipherSuite::getCipherSuiteName)
        .orElse("UNKNOWN(" + tuple + ")");
  }

  /**
   * Formats a TLS-1.3 signature-scheme byte pair as a readable signature-scheme summary.
   *
   * @param firstByte first logged signature-scheme byte
   * @param secondByte second logged signature-scheme byte
   * @return matching signature-scheme summary, or a raw unknown marker
   */
  private static String formatTls13SignatureScheme(String firstByte, String secondByte) {
    var tuple = formatHexBytePair(firstByte, secondByte);
    return Arrays.stream(TlsSignatureSchemes.values())
        .filter(signatureScheme -> signatureScheme.getHexValue().equalsIgnoreCase(tuple))
        .findFirst()
        .map(signatureScheme -> signatureScheme.name()
            + "("
            + signatureScheme.getSchemeName()
            + "/"
            + signatureScheme.getHexValue()
            + ")")
        .orElse("UNKNOWN(" + tuple + ")");
  }

  /**
   * Formats a TLS supported-group byte pair as a readable supported-group summary.
   *
   * @param firstByte first logged supported-group byte
   * @param secondByte second logged supported-group byte
   * @return matching supported-group summary, or a raw unknown marker
   */
  private static String formatTlsSupportedGroup(String firstByte, String secondByte) {
    var groupId = Integer.parseInt(firstByte + secondByte, 16);
    var group = TlsSupportedGroup.fromValue(groupId);
    var groupName = group == TlsSupportedGroup.UNKNOWN ? "UNKNOWN" : group.getDisplayName();
    return groupName + "(" + formatHexWord(groupId) + ")";
  }

  /**
   * Formats two hex bytes in the tuple syntax used by the tls-test-tool configuration.
   *
   * @param firstByte first logged byte
   * @param secondByte second logged byte
   * @return normalized tuple, e.g. {@code (0x13,0x01)}
   */
  private static String formatHexBytePair(String firstByte, String secondByte) {
    return "(0x%s,0x%s)".formatted(firstByte.toUpperCase(Locale.ROOT), secondByte.toUpperCase(Locale.ROOT));
  }

  /**
   * Formats an unsigned 16-bit protocol value as uppercase hex.
   *
   * @param value unsigned 16-bit value
   * @return normalized hex word, e.g. {@code 0x001D}
   */
  private static String formatHexWord(int value) {
    return "0x%04X".formatted(value & 0xFFFF);
  }

  /**
   * Extract the most relevant handshake phase from the TLS logs as a single string.
   *
   * @return TLS log excerpt containing the current or failing handshake phase
   */
  private String extractRelevantLogPhase() {
    if (tlsLogs == null || tlsLogs.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }
    var lines = Arrays.stream(tlsLogs.split("\\R")).toList();
    var relevantPhase = determineRelevantLogPhase(lines);
    return String.join(System.lineSeparator(), lines.subList(relevantPhase.startInclusive(), relevantPhase.endExclusive()));
  }

  /**
   * Determine the most relevant handshake phase in the TLS logs.
   *
   * <p>If a handshake failure is present, the phase ending at the last failure line is selected.
   * Otherwise, the latest observed handshake phase is used.</p>
   *
   * @param lines TLS log lines
   * @return selected handshake phase boundaries
   */
  private TlsLogPhase determineRelevantLogPhase(List<String> lines) {
    var failureIndex = -1;
    for (var i = 0; i < lines.size(); i++) {
      if (TLS_HANDSHAKE_FAILED_PATTERN.matcher(lines.get(i)).find()) {
        failureIndex = i;
      }
    }
    var endExclusive = failureIndex >= 0 ? failureIndex + 1 : lines.size();
    var startInclusive = 0;
    for (var i = 0; i < endExclusive; i++) {
      if (isHandshakePhaseBoundary(lines.get(i))) {
        startInclusive = i + 1;
      }
    }
    return new TlsLogPhase(startInclusive, endExclusive);
  }

  /**
   * Checks whether a log line marks a new handshake phase boundary.
   *
   * @param line log line
   * @return {@code true} if the line indicates start of a new handshake phase
   */
  private boolean isHandshakePhaseBoundary(String line) {
    return TLS_RENEGOTIATION_PHASE_PATTERN.matcher(line).find()
        || TLS_CLIENT_HELLO_SENT_PATTERN.matcher(line).find()
        || TLS_CLIENT_HELLO_WRITE_PATTERN.matcher(line).find();
  }

  /**
   * Build a short summary that explains which TLS1.2 hash algorithms were offered and whether the server selected a concrete hash algorithm
   * in the observed logs.
   *
   * @return hash negotiation summary
   */
  private String buildHashNegotiationSummary() {
    if (lastOfferedTlsHashAlgorithms.isEmpty()) {
      return "Hash negotiation: no explicit TLS1.2 hash offer context captured.";
    }
    var selected = extractSelectedTls12HashAlgorithm();
    return (selected == null)
        ? ("Hash negotiation: offered="
        + lastOfferedTlsHashAlgorithms
        + ", selected=n/a (handshake likely aborted before ServerKeyExchange hash selection).")
        : ("Hash negotiation: offered="
            + lastOfferedTlsHashAlgorithms
            + ", selected="
            + selected
            + ", selected_offered="
            + lastOfferedTlsHashAlgorithms.contains(selected)
            + ".");
  }

  /**
   * Extract the hash algorithm selected by the server in TLS 1.2 ServerKeyExchange logs.
   *
   * @return selected hash algorithm, or {@code null} if not present in the logs
   */
  private TlsHashAlgorithm extractSelectedTls12HashAlgorithm() {
    if (tlsLogs == null || tlsLogs.isBlank()) {
      return null;
    }
    var matcher = TLS_HASH_ALGORITHM_PATTERN.matcher(tlsLogs);
    if (!matcher.find()) {
      return null;
    }
    var id = Integer.parseInt(matcher.group(1));
    return TlsHashAlgorithm.fromValue(id);
  }

  /**
   * Map textual hash names from feature tables to canonical TLS hash enum values.
   *
   * @param names hash names such as {@code SHA256} or {@code RSA_SHA256}
   * @return insertion-ordered set of mapped hash algorithms
   */
  private LinkedHashSet<TlsHashAlgorithm> mapNamesToHashAlgorithms(Set<String> names) {
    return names.stream()
        .filter(Objects::nonNull)
        .map(String::trim)
        .filter(name -> !name.isEmpty())
        .map(TlsHashAlgorithm::fromDisplayName)
        .filter(Objects::nonNull)
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  /**
   * Parses non-empty first-column values from a Cucumber data table.
   *
   * @param table data table containing values in the first column
   * @param setFactory target set factory
   * @param <S> target set type
   * @return set of normalized first-column values
   */
  private static <S extends Set<String>> S parseNonEmptyFirstColumn(DataTable table, Supplier<S> setFactory) {
    return table
        .asLists()
        .stream()
        .filter(row -> row != null && !row.isEmpty())
        .map(row -> row.getFirst() != null ? row.getFirst().trim() : "")
        .filter(value -> !value.isEmpty())
        .collect(Collectors.toCollection(setFactory));
  }

  /**
   * Ensures TLS logs are available for assertions.
   */
  private void requireTlsLogs() {
    if (tlsLogs == null || tlsLogs.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }
  }

  /**
   * Creates and runs a TLS 1.2 client scenario with configurable hash and group extensions.
   *
   * @param host host to be tested
   * @param tlsCipherSuites tls-test-tool formatted cipher-suite configuration line
   * @param tlsSignatureHashAlgos tls-test-tool formatted signature hash algorithms extension
   * @param tlsSupportedGroups tls-test-tool formatted supported-groups extension
   * @param offeredHashAlgorithms hash algorithms to log for traceability
   * @param enableRenegotiation whether to append renegotiation trigger to the config
   */
  private void runTls12ClientScenario(
      String host,
      String tlsCipherSuites,
      String tlsSignatureHashAlgos,
      String tlsSupportedGroups,
      Iterable<?> offeredHashAlgorithms,
      boolean enableRenegotiation) {
    checkHost(host);

    log.info("ClientHello only offers the following TLS 1.2 signature hash algorithms:");
    for (var hashAlgorithm : offeredHashAlgorithms) {
      log.info("{}", hashAlgorithm);
    }

    var tlsTestToolConfigBuffer = getTls12TestToolConfigBuffer(
        tlsSignatureHashAlgos, tlsSupportedGroups, tlsCipherSuites, host);
    if (enableRenegotiation) {
      // Add configuration to initiate a TLS handshake renegotiation.
      tlsTestToolConfigBuffer += "manipulateRenegotiate=\n";
    }
    runTlsTestToolClient(tlsTestToolConfigBuffer);
  }

  /**
   * Creates and runs a TLS 1.3 client scenario.
   *
   * @param host host to be tested
   * @param tlsCipherSuites tls-test-tool formatted cipher-suite configuration line
   * @param supportedSchemeNames TLS-1.3 signature-scheme names to log for traceability
   * @param supportedSchemeHexValues tls-test-tool formatted TLS-1.3 signature-schemes value
   * @param tlsSupportedGroups TLS-1.3 supported_groups value
   */
  private void runTls13ClientScenario(
      String host,
      String tlsCipherSuites,
      Iterable<?> supportedSchemeNames,
      String supportedSchemeHexValues,
      String tlsSupportedGroups) {

    checkHost(host);
    Objects.requireNonNull(supportedSchemeHexValues, "supportedSchemeHexValues must not be null");
    Objects.requireNonNull(tlsSupportedGroups, "tlsSupportedGroups must not be null");

    log.info("ClientHello only offers the following TLS 1.3 signature schemes:");
    for (var supportedScheme : supportedSchemeNames) {
      log.info("{}", supportedScheme);
    }

    log.info("ClientHello only offers the following TLS 1.3 supported groups: {}", tlsSupportedGroups);

    var tlsTestToolConfigBuffer = getTls13TestToolConfigBuffer(
        supportedSchemeHexValues, tlsSupportedGroups, tlsCipherSuites, host);

    runTlsTestToolClient(tlsTestToolConfigBuffer);
  }

  /**
   * Checks whether the server certificate uses TR-02102-2-recommended key lengths and domain parameters.
   */
  @Dann("verwendet der Server ein Zertifikat mit Schlüssellängen und Domainparameter nach [TR-02102-2]")
  @Then("the server uses a certificate with key lengths and domain parameters according to [TR-02102-2]")
    public void checkServerCertificateUsesRecommendedKeyLengthsAndDomainParameters() {
    requireTlsLogs();

    var der = extractCertificateFromLog(tlsLogs);
    if (der == null || der.length == 0) {
      throw new AssertionError("No certificate hex dump found in the log.");
    }

    X509Certificate cert;
    try {
      cert = parseAsX509(der);
    } catch (CertificateException e) {
      throw new AssertionError("Error parsing the certificate", e);
    }

    var pk = cert.getPublicKey();
    if (!(pk instanceof ECPublicKey ecPk)) {
      throw new AssertionError("The X.509 certificate public key is not EC.");
    }

    var curveOid = getNamedCurveOid(cert);
    if (curveOid == null) {
      throw new AssertionError("The X.509 certificate EC curve is missing or can not be determined.");
    }

    var selectedCurve = getSupportedGroupFromCurveOid(curveOid);
    var fieldSize = ecPk.getParams().getCurve().getField().getFieldSize();
    Assertions
        .assertThat(selectedCurve.getTls12Policy())
        .withFailMessage(
            "Certificate EC curve OID %s resolves to %s with non-recommended policy %s. Field size=%d",
            curveOid,
            selectedCurve.getDisplayName(),
            selectedCurve.getTls12Policy(),
            fieldSize)
        .isIn(TlsSupportedGroup.Tls12Policy.MANDATORY, TlsSupportedGroup.Tls12Policy.OPTIONAL);

    Assertions
        .assertThat(fieldSize)
        // A_28868 / TR-02102-2 section 3.6.1: static and ephemeral ECDH keys require at least 250-bit strength.
        .withFailMessage(
            "Certificate EC key length/domain parameters are not recommended by TR-02102-2. Curve=%s, OID=%s, field size=%d",
            selectedCurve.getDisplayName(),
            curveOid,
            fieldSize)
        .isGreaterThanOrEqualTo(250);
  }

  /**
   * Creates a TLS 1.2 test tool configuration and executes the tool.
   *
   * @param host            Host to be tested
   * @param tlsCipherSuites Cipher suites configuration string for the test tool
   */
  private void runTls12TestTool(String host, String tlsCipherSuites) {
    runTls12ClientScenario(
        host,
        tlsCipherSuites,
        SUPPORTED_SIGNATURE_HASH_ALGOS,
        VALID_SUPPORTED_GROUPS,
        TlsHashAlgorithm.supportedByPolicy(),
        false);
  }

  /**
   * Creates a TLS 1.2 server configuration and starts the service-managed TLS test tool server.
   *
   * @param tlsCipherSuites Cipher suites configuration string for the test tool
   */
  private void runTls12TestToolServer(String tlsCipherSuites) {

    var tlsTestToolConfigBuffer = getTlsTestToolServerBaseConfig(tlsCipherSuites);
    runTlsTestToolServer(tlsTestToolConfigBuffer);
  }

  /**
   * Clears cached logs and service-backed run lifecycle markers before a new run starts.
   */
  private void clearTlsLogCollectors() {
    tlsLogs = "";
    tlsTestToolStarted = false;
  }

  /**
   * Check if the host is empty or null.
   *
   * @param host host value to validate
   */
  void checkHost(String host) {
    if (host == null || host.isBlank()) {
      throw new AssertionError("The host is empty or null.");
    }
    log.info("Performing the TLS-Test for host: {}", host);
  }

  /**
   * Executes the TLS test tool in client mode via the TLS test tool service.
   *
   * <p>The previous service-managed process is stopped first and the retained remote logs are cleared
   * before the generated config file and CA certificate are uploaded. The new client run is then
   * started through the service endpoint.</p>
   *
   * @param tlsTestToolConfigBuffer TLS test tool configuration content
   */
  void runTlsTestToolClient(String tlsTestToolConfigBuffer) {
    var configFileLocation = Path.of(createTempConfigFile(tlsTestToolConfigBuffer));
    var caCertificateFile = resolveCaCertificatePath();
    log.debug("TLS Test Tool service configuration file path: {}", configFileLocation);
    log.debug("TLS Test Tool service CA certificate file path: {}", caCertificateFile);

    clearTlsLogCollectors();
    var tlsTestToolService = TlsTestToolServiceFactory.getInstance();
    tlsTestToolService.stop();
    tlsTestToolService.clearLogs();
    tlsTestToolService.updateConfig(configFileLocation);
    tlsTestToolService.updateCaCertificate(caCertificateFile);
    tlsTestToolService.startAsTlsClient();
    tlsTestToolStarted = true;
  }

  /**
   * Starts the TLS test tool server through the TLS test tool service using the default certificate.
   *
   * @param tlsTestToolConfigBuffer TLS test tool server configuration content
   */
  void runTlsTestToolServer(String tlsTestToolConfigBuffer) {
    runTlsTestToolServer(tlsTestToolConfigBuffer, TlsServerCertificates.ZETA_TLS_TEST_TOOL_SERVER_ECDSA_GOOD_CERTIFICATE);
  }

  /**
   * Executes the TLS test tool in server mode via the TLS test tool service.
   *
   * <p>The previous service-managed process is stopped first and the retained remote logs are cleared
   * before the generated config file, certificate, and private key are uploaded. The new server
   * instance is then started through the service endpoint.</p>
   *
   * @param tlsTestToolConfigBuffer TLS test tool server configuration content
   * @param serverCertificate certificate descriptor to upload; defaults to the standard certificate when {@code null}
   */
  void runTlsTestToolServer(String tlsTestToolConfigBuffer, TlsServerCertificates serverCertificate) {
    var effectiveServerCertificate = serverCertificate == null ? TlsServerCertificates.ZETA_TLS_TEST_TOOL_SERVER_ECDSA_GOOD_CERTIFICATE : serverCertificate;
    var configFileLocation = Path.of(createTempConfigFile(tlsTestToolConfigBuffer));
    var certificateFile = Path.of(resolveCertificateOrKeyPath(effectiveServerCertificate.relativePath));
    var privateKeyFile = Path.of(
        resolveCertificateOrKeyPath(TlsServerCertificates.getPrivateKeyForCertificate(effectiveServerCertificate).relativePath));
    var caCertificateFile = resolveCaCertificatePath();

    log.debug("TLS Test Tool service configuration file path: {}", configFileLocation);
    log.debug("TLS Test Tool service certificate file path: {}", certificateFile);
    log.debug("TLS Test Tool service private key file path: {}", privateKeyFile);
    log.debug("TLS Test Tool service CA certificate file path: {}", caCertificateFile);

    clearTlsLogCollectors();
    var tlsTestToolService = TlsTestToolServiceFactory.getInstance();
    tlsTestToolService.stop();
    tlsTestToolService.clearLogs();
    tlsTestToolService.updateConfig(configFileLocation);
    tlsTestToolService.updateCertificate(certificateFile, privateKeyFile);
    tlsTestToolService.updateCaCertificate(caCertificateFile);
    tlsTestToolService.startAsTlsServer();
    tlsTestToolStarted = true;
  }

  /**
   * Saves the currently cached TLS test tool logs to the Serenity report.
   */
  private void saveTlsLogsToSerenityReport() {
    requireTlsLogs();
    log.debug("TLS Test Tool Logs:");
    log.debug(tlsLogs);

    Serenity.recordReportData()
        .withTitle("TLS Test Tool Logs:")
        .andContents(tlsLogs);
  }

  /**
   * Retrieves logs for a previously started TLS test tool run and stores them in the report.
   */
  @Dann("die Tls-Test-Tool-Protokolle abrufen")
  @Then("the TLS test tool logs are retrieved")
  public void getTheTlsTestToolLogs() {
    if (!tlsTestToolStarted) {
      throw new AssertionError("TLS test tool has not been started.");
    }
    tlsLogs = TlsTestToolServiceFactory.getInstance().getLogs();
    saveTlsLogsToSerenityReport();
  }

  /**
   * Creates a temporary configuration file for the TLS test tool.
   *
   * @param contents configuration content to write
   * @return created temp file path
   */
  private String createTempConfigFile(String contents) {

    if (contents == null || contents.isBlank()) {
      throw new AssertionError("The content is empty or null.");
    }

    Path tempFile;
    try {
      tempFile = Files.createTempFile("tls-test-tool", ".conf");
    } catch (java.io.IOException e) {
      throw new AssertionError("Error creating file: tls-test-tool.conf", e);
    }

    try (var writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
      writer.write(contents);
    } catch (java.io.IOException e) {
      throw new AssertionError("Error writing to file: " + tempFile, e);
    }

    log.info("Created temporary TLS test tool configuration file: {}", tempFile);
    log.debug(contents);
    return tempFile.toString();
  }

  /**
   * Builds a TLS-1.3 server configuration for all policy-supported cipher suites.
   *
   * @return generated TLS test tool server configuration
   */
  private static @NonNull String buildTls13ServerConfigForSupportedCipherSuites() {
    return buildTls13ServerConfig(buildSupportedCipherSuitesValue(TlsVersion.TLS_1_3));
  }

  /**
   * Builds a TLS-1.2 server configuration for the provided cipher suites and optional extra config lines.
   *
   * @param cipherSuites cipher suites in tls-test-tool tuple syntax
   * @param extraConfigLines additional config lines without trailing newline
   * @return generated TLS test tool server configuration
   */
  private static @NonNull String buildTls12ServerConfig(String cipherSuites, String... extraConfigLines) {
    return buildTlsServerConfig(getTlsTestToolServerBaseConfig(), cipherSuites, extraConfigLines);
  }

  /**
   * Builds a TLS-1.3 server configuration for the provided cipher suites and optional extra config lines.
   *
   * @param cipherSuites cipher suites in tls-test-tool tuple syntax
   * @param extraConfigLines additional config lines without trailing newline
   * @return generated TLS test tool server configuration
   */
  private static @NonNull String buildTls13ServerConfig(String cipherSuites, String... extraConfigLines) {
    return buildTlsServerConfig(getTls13TestToolServerBaseConfig(TlsLibrary.OPENSSL), cipherSuites, extraConfigLines);
  }

  /**
   * Builds a TLS server configuration from a base config, cipher suites, and optional extra config lines.
   *
   * @param baseConfig TLS server base configuration
   * @param cipherSuites cipher suites in tls-test-tool tuple syntax
   * @param extraConfigLines additional config lines without trailing newline
   * @return generated TLS test tool server configuration
   */
  private static @NonNull String buildTlsServerConfig(String baseConfig, String cipherSuites, String... extraConfigLines) {
    if (cipherSuites == null || cipherSuites.isBlank()) {
      throw new AssertionError("The Cipher Suite value is empty or null.");
    }

    var configBuilder = new StringBuilder(baseConfig)
        .append("tlsCipherSuites=")
        .append(cipherSuites)
        .append("\n");

    if (extraConfigLines != null) {
      for (String extraConfigLine : extraConfigLines) {
        if (extraConfigLine != null && !extraConfigLine.isBlank()) {
          configBuilder.append(extraConfigLine).append("\n");
        }
      }
    }
    return configBuilder.toString();
  }

  /**
   * Returns all supported cipher suites for the given TLS version in tls-test-tool tuple syntax.
   *
   * @param tlsVersion TLS version whose supported cipher suites should be returned
   * @return comma-separated supported cipher suites
   */
  private static @NonNull String buildSupportedCipherSuitesValue(TlsVersion tlsVersion) {
    if (tlsVersion == null) {
      throw new AssertionError("The TLS version is null.");
    }

    var cipherSuites = switch (tlsVersion) {
      case TLS_1_2 -> TlsCipherSuite.supportedTls12CipherSuites().stream();
      case TLS_1_3 -> TlsCipherSuite.supportedTls13CipherSuites().stream();
    };

    return cipherSuites
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.joining(","));
  }

  /**
   * Asserts that a parsed TLS structure is non-empty and contains only allowed values.
   *
   * @param actualValues parsed values
   * @param isAllowed predicate that defines whether a value is policy-compliant
   * @param emptyMessage failure message for an empty value set
   * @param mismatchMessage failure message template for unsupported values
   * @param <T> parsed value type
   */
  private static <T> void assertOnlyAllowedValues(
      List<T> actualValues,
      Predicate<T> isAllowed,
      String emptyMessage,
      String mismatchMessage) {
    Assertions
        .assertThat(actualValues.isEmpty())
        .withFailMessage(emptyMessage)
        .isFalse();

    List<T> mismatches = actualValues.stream()
        .filter(isAllowed.negate())
        .distinct()
        .toList();

    Assertions
        .assertThat(mismatches.isEmpty())
        .withFailMessage(mismatchMessage, mismatches)
        .isTrue();
  }

  /**
   * Checks whether the server sends a renegotiation_info extension in the ServerHello record.
   */
  @Dann("ist die Erweiterung renegotiation_info im ServerHello vorhanden")
  @Then("the renegotiation_info extension is present in the ServerHello")
  public void checkIfRenegotiationInfoExtensionIsPresentInServerHello() {
    Assertions
        .assertThat(helloHasEmptyRenegotiationInfo(TlsEndpointRole.SERVER))
        .withFailMessage("The renegotiation_info could not be found in the TLS ServerHello.")
        .isTrue();
  }

  /**
   * Checks whether the client sends a renegotiation_info extension in the ClientHello record.
   *
   * @return true if renegotiation_info (0xff01) is present with length == 0
   */
  private boolean clientHelloHasEmptyRenegotiationInfo() {
    return helloHasEmptyRenegotiationInfo(TlsEndpointRole.CLIENT);
  }

  /**
   * Checks whether the renegotiation_info extension is present.
   *
   * @param role TLS endpoint role
   * @return true if renegotiation_info (0xff01) is present with length == 0
   */
  private boolean helloHasEmptyRenegotiationInfo(TlsEndpointRole role) {
    requireTlsLogs();

    byte[] renegotiationInfo = findExtensionData(
        extractHelloExtensions(
            tlsLogs,
            role == TlsEndpointRole.SERVER
                ? SERVER_HELLO_EXTENSIONS_PATTERN
                : CLIENT_HELLO_EXTENSIONS_OPTIONAL_PATTERN,
            false),
        0xFF01);
    return renegotiationInfo != null && renegotiationInfo.length == 1 && renegotiationInfo[0] == 0x00;
  }

  /**
   * Extracts ClientHello.cipher_suite.
   *
   * @param tlsLog TLS log content
   * @return cipher suites pairs ["(0xC0,0x2C)", "(0xC0,0x30)", ...]
   * @throws AssertionError if {@code tlsLog} is {@code null} or blank
   */
  private static List<String> extractClientHelloCipherSuitesAsPairs(String tlsLog) {
    if (tlsLog == null || tlsLog.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }
    Matcher m = CLIENT_HELLO_CIPHER_SUITES_PATTERN.matcher(tlsLog);
    if (!m.find()) {
      return List.of();
    }

    String[] bytes = m.group(1).trim().split("\\s+");
    List<String> pairs = new ArrayList<>(bytes.length / 2);
    for (int i = 0; i + 1 < bytes.length; i += 2) {
      pairs.add("(0x" + bytes[i].toUpperCase(Locale.ROOT) + ",0x" + bytes[i + 1].toUpperCase(Locale.ROOT) + ")");
    }
    return pairs;
  }

  /**
   * Checks whether the ClientHello TLS version is 1.2.
   */
  @Dann("die ClientHello-TLS-Version ist 1.2")
  @Then("the ClientHello TLS version is 1.2")
  public void checkIfClientHelloTlsVersionIs1_2() {
    requireTlsLogs();

    // Checks if the client supports TLS 1.2
    Assertions
        .assertThat(tlsLogs.contains("ClientHello.client_version=03 03"))
        .withFailMessage("TLS 1.2 is not supported by the client.")
        .isTrue();
  }

  /**
   * Checks whether the client hello only contains cipher suites specified in TR-02102-2, Abschnitt 3.3.1 Tabelle 1.
   * TLS 1.3 cipher suites are also accepted and do not cause this test step to fail if they are present.
   */
  @Dann("der ClientHello-Record enthält nur Cipher-Suiten aus TR-02102-2, Abschnitt 3.3.1 Tabelle 1")
  @Then("the ClientHello record contains only cipher suites from TR-02102-2, section 3.3.1 table 1")
  public void onlySupportedCipherSuitesArePresent() {
    requireTlsLogs();

    List<String> offered = extractClientHelloCipherSuitesAsPairs(tlsLogs);
    Assertions
        .assertThat(offered.isEmpty())
        .withFailMessage("No ClientHello.cipher_suites found in log.")
        .isFalse();

    // HashSet for fast membership checks
    HashSet<String> supportedCipherSuites = TlsCipherSuite.supportedTls12CipherSuites().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.toCollection(HashSet::new));
    supportedCipherSuites.addAll(TlsCipherSuite.supportedTls13CipherSuites().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.toSet()));

    // Find any non-supported cipher suites
    List<String> notSupported = offered.stream()
        .filter(cs -> !supportedCipherSuites.contains(cs))
        .toList();

    Assertions
        .assertThat(notSupported.isEmpty())
        .withFailMessage("The following un-supported Cipher Suites were advertised by the Client. %s", notSupported)
        .isTrue();
  }

  /**
   * Checks whether the client hello only contains cipher suites from  A_28868 and none specified in TR-02102-2, Abschnitt 3.3.1 Tabelle 1.
   * TLS 1.3 cipher suites are also accepted and do not cause this test step to fail if they are present.
   */
  @Dann("der ClientHello-Record enthält keine optionalen Cipher-Suiten aus TR-02102-2, Abschnitt 3.3.1 Tabelle 1")
  @Then("the ClientHello record contains no optional cipher suites from TR-02102-2, section 3.3.1 table 1")
  public void onlySupportedCipherSuitesArePresentWithoutOptional() {
    requireTlsLogs();

    List<String> offered = extractClientHelloCipherSuitesAsPairs(tlsLogs);
    Assertions
        .assertThat(offered.isEmpty())
        .withFailMessage("No ClientHello.cipher_suites found in log.")
        .isFalse();

    // HashSet for fast membership checks
    HashSet<String> supportedCipherSuites = TlsCipherSuite.supportedTls12CipherSuitesWithoutOptional().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.toCollection(HashSet::new));
    supportedCipherSuites.addAll(TlsCipherSuite.supportedTls13CipherSuitesWithoutOptional().stream()
        .map(TlsCipherSuite::getTlsTestToolCipherSuiteValue)
        .collect(Collectors.toSet()));

    // Find any non-supported cipher suites
    List<String> notSupported = offered.stream()
        .filter(cs -> !supportedCipherSuites.contains(cs))
        .toList();

    Assertions
        .assertThat(notSupported.isEmpty())
        .withFailMessage("The following un-supported Cipher Suites were advertised by the Client. %s", notSupported)
        .isTrue();
  }

  /**
   * Checks whether the client hello only contains the TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite or
   * an empty renegotiation_info extension.
   */
  @Dann("der ClientHello-Record enthält TLS_EMPTY_RENEGOTIATION_INFO_SCSV oder eine leere renegotiation_info extension")
  @Then("the ClientHello record contains TLS_EMPTY_RENEGOTIATION_INFO_SCSV or an empty renegotiation_info extension")
  public void scsvCipherSuiteOrRenegotiationInfoArePresent() {
    requireTlsLogs();

    // RFC 5746 is satisfied if either the empty renegotiation_info extension is present
    // or TLS_EMPTY_RENEGOTIATION_INFO_SCSV is offered in the ClientHello.
    if (clientHelloHasEmptyRenegotiationInfo()) {
      return;
    }

    List<String> offered = extractClientHelloCipherSuitesAsPairs(tlsLogs);
    Assertions
        .assertThat(offered.isEmpty())
        .withFailMessage(
            "Neither an empty renegotiation_info extension nor ClientHello.cipher_suites were found in log.")
        .isFalse();

    // Check if the EMPTY_RENEGOTIATION_INFO_SCSV cipher suite is present
    boolean hasEmptyRenegotiationInfoScsv =
        offered.stream()
            .filter(Objects::nonNull)
            .map(String::trim)
            .anyMatch(s ->
                s.equalsIgnoreCase(TlsCipherSuite.EMPTY_RENEGOTIATION_INFO_SCSV.getTlsTestToolCipherSuiteValue())
            );

    Assertions
        .assertThat(hasEmptyRenegotiationInfoScsv)
        .withFailMessage(
            "The EMPTY_RENEGOTIATION_INFO_SCSV or the correct renegotiation_info could not be found in the TLS Client Hello.")
        .isTrue();
  }

  /**
   * Supported/required signature hash algorithms.
   */
  private enum SignatureAndHashAlgorithms {
    RSA_MD5,
    RSA_SHA1,
    RSA_SHA224,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
  }

  /**
   * TLS-1.3 signature schemes with wire-format hex values and recommendation metadata.
   */
  private enum TlsSignatureSchemes {
    RSA_PKCS1_MD5("rsa_pkcs1_md5", "(0x01,0x01)", Tls13Policy.FORBIDDEN),
    DSA_MD5("dsa_md5", "(0x01,0x02)", Tls13Policy.FORBIDDEN),
    ECDSA_MD5("ecdsa_md5", "(0x01,0x03)", Tls13Policy.FORBIDDEN),
    RSA_PKCS1_SHA1("rsa_pkcs1_sha1", "(0x02,0x01)", Tls13Policy.FORBIDDEN),
    DSA_SHA1("dsa_sha1", "(0x02,0x02)", Tls13Policy.FORBIDDEN),
    ECDSA_SHA1("ecdsa_sha1", "(0x02,0x03)", Tls13Policy.FORBIDDEN),
    RSA_PKCS1_SHA224("rsa_pkcs1_sha224", "(0x03,0x01)", Tls13Policy.FORBIDDEN),
    DSA_SHA224("dsa_sha224", "(0x03,0x02)", Tls13Policy.FORBIDDEN),
    ECDSA_SHA224("ecdsa_sha224", "(0x03,0x03)", Tls13Policy.FORBIDDEN),
    RSA_PKCS1_SHA256("rsa_pkcs1_sha256", "(0x04,0x01)", Tls13Policy.LEGACY_DISALLOWED),
    DSA_SHA256("dsa_sha256", "(0x04,0x02)", Tls13Policy.FORBIDDEN),
    RSA_PKCS1_SHA384("rsa_pkcs1_sha384", "(0x05,0x01)", Tls13Policy.LEGACY_DISALLOWED),
    DSA_SHA384("dsa_sha384", "(0x05,0x02)", Tls13Policy.FORBIDDEN),
    RSA_PKCS1_SHA512("rsa_pkcs1_sha512", "(0x06,0x01)", Tls13Policy.LEGACY_DISALLOWED),
    DSA_SHA512("dsa_sha512", "(0x06,0x02)", Tls13Policy.FORBIDDEN),
    RSA_PSS_RSAE_SHA256("rsa_pss_rsae_sha256", "(0x08,0x04)", Tls13Policy.CURVE_DISALLOWED),
    RSA_PSS_RSAE_SHA384("rsa_pss_rsae_sha384", "(0x08,0x05)", Tls13Policy.CURVE_DISALLOWED),
    RSA_PSS_RSAE_SHA512("rsa_pss_rsae_sha512", "(0x08,0x06)", Tls13Policy.CURVE_DISALLOWED),
    ED25519("ed25519", "(0x08,0x07)", Tls13Policy.CURVE_DISALLOWED),
    ED448("ed448", "(0x08,0x08)", Tls13Policy.CURVE_DISALLOWED),
    RSA_PSS_PSS_SHA256("rsa_pss_pss_sha256", "(0x08,0x09)", Tls13Policy.CURVE_DISALLOWED),
    RSA_PSS_PSS_SHA384("rsa_pss_pss_sha384", "(0x08,0x0A)", Tls13Policy.CURVE_DISALLOWED),
    RSA_PSS_PSS_SHA512("rsa_pss_pss_sha512", "(0x08,0x0B)", Tls13Policy.CURVE_DISALLOWED),
    ECDSA_SECP256R1_SHA256("ecdsa_secp256r1_sha256", "(0x04,0x03)", Tls13Policy.RECOMMENDED),
    ECDSA_SECP384R1_SHA384("ecdsa_secp384r1_sha384", "(0x05,0x03)", Tls13Policy.RECOMMENDED),
    ECDSA_SECP521R1_SHA512("ecdsa_secp521r1_sha512", "(0x06,0x03)", Tls13Policy.CURVE_DISALLOWED),
    ECDSA_BRAINPOOLP256R1TLS13_SHA256("ecdsa_brainpoolP256r1tls13_sha256", "(0x08,0x1A)", Tls13Policy.RECOMMENDED),
    ECDSA_BRAINPOOLP384R1TLS13_SHA384("ecdsa_brainpoolP384r1tls13_sha384", "(0x08,0x1B)", Tls13Policy.RECOMMENDED),
    ECDSA_BRAINPOOLP512R1TLS13_SHA512("ecdsa_brainpoolP512r1tls13_sha512", "(0x08,0x1C)", Tls13Policy.RECOMMENDED);

    /**
     * TLS-1.3-specific recommendation classification for signature schemes.
     */
    private enum Tls13Policy {
      RECOMMENDED,
      LEGACY_DISALLOWED,
      CURVE_DISALLOWED,
      FORBIDDEN,
      NA
    }

    @Getter
    private final String schemeName;
    @Getter
    private final String hexValue;
    @Getter
    private final Tls13Policy tls13Policy;

    TlsSignatureSchemes(String schemeName, String hexValue, Tls13Policy tls13Policy) {
      this.schemeName = schemeName;
      this.hexValue = hexValue;
      this.tls13Policy = tls13Policy;
    }

    /**
     * Returns the recommended TLS-1.3 signature scheme names expected in Gherkin tables.
     *
     * @return set of recommended TLS-1.3 signature scheme names
     */
    public static Set<String> recommendedSchemeNames() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.RECOMMENDED)
          .map(TlsSignatureSchemes::getSchemeName)
          .collect(Collectors.toCollection(HashSet::new));
    }

    /**
     * Returns the non-recommended TLS-1.3 signature scheme names expected in Gherkin tables.
     *
     * @return set of non-recommended TLS-1.3 signature scheme names
     */
    public static Set<String> nonRecommendedSchemeNames() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.LEGACY_DISALLOWED)
          .map(TlsSignatureSchemes::getSchemeName)
          .collect(Collectors.toCollection(HashSet::new));
    }

    /**
     * Returns all TLS-1.3 signature schemes that are not permitted by the current policy.
     *
     * @return list of unsupported TLS-1.3 signature schemes
     */
    public static List<TlsSignatureSchemes> unsupportedSchemes() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() != Tls13Policy.RECOMMENDED)
          .filter(scheme -> scheme.getTls13Policy() != Tls13Policy.NA)
          .collect(Collectors.toList());
    }

    /**
     * Returns all TLS-1.3 RSA signature schemes that are not permitted by the current policy.
     *
     * @return list of unsupported TLS-1.3 RSA signature schemes
     */
    public static List<TlsSignatureSchemes> unsupportedRsaSchemes() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.name().startsWith("RSA_"))
          .filter(scheme -> scheme.getTls13Policy() != Tls13Policy.RECOMMENDED)
          .filter(scheme -> scheme.getTls13Policy() != Tls13Policy.NA)
          .collect(Collectors.toList());
    }

    /**
     * Returns the tls-test-tool configuration value for the recommended TLS-1.3 signature schemes.
     *
     * @return comma-separated list in tls-test-tool tuple syntax
     */
    public static String recommendedSchemeHexValues() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.RECOMMENDED)
          .map(TlsSignatureSchemes::getHexValue)
          .collect(Collectors.joining(","));
    }

    /**
     * Returns the tls-test-tool configuration value for the given TLS-1.3 signature scheme names.
     *
     * @param schemeNames TLS-1.3 signature scheme names
     * @return comma-separated list in tls-test-tool tuple syntax
     */
    public static String schemeHexValuesForSchemeNames(Set<String> schemeNames) {
      if (schemeNames == null || schemeNames.isEmpty()) {
        throw new AssertionError("The TLS 1.3 signature scheme names are empty or null.");
      }

      return Arrays.stream(values())
          .filter(scheme -> schemeNames.contains(scheme.getSchemeName()))
          .map(TlsSignatureSchemes::getHexValue)
          .collect(Collectors.joining(","));
    }

    /**
     * Returns the recommended TLS-1.3 signature scheme names for the given hash algorithms.
     *
     * @param hashAlgorithms supported hash algorithms
     * @return set of recommended TLS-1.3 signature scheme names matching the provided hashes
     */
    public static Set<String> recommendedSchemeNamesForHashes(Set<TlsHashAlgorithm> hashAlgorithms) {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.RECOMMENDED)
          .filter(scheme -> scheme.matchesAnyHash(hashAlgorithms))
          .map(TlsSignatureSchemes::getSchemeName)
          .collect(Collectors.toCollection(HashSet::new));
    }

    /**
     * Returns the tls-test-tool configuration value for the recommended TLS-1.3 signature schemes
     * matching the given hash algorithms.
     *
     * @param hashAlgorithms supported hash algorithms
     * @return comma-separated list in tls-test-tool tuple syntax
     */
    public static String recommendedSchemeHexValuesForHashes(Set<TlsHashAlgorithm> hashAlgorithms) {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.RECOMMENDED)
          .filter(scheme -> scheme.matchesAnyHash(hashAlgorithms))
          .map(TlsSignatureSchemes::getHexValue)
          .collect(Collectors.joining(","));
    }

    /**
     * Returns the tls-test-tool configuration value for the non-recommended TLS-1.3 signature schemes.
     *
     * @return comma-separated list in tls-test-tool tuple syntax
     */
    public static String nonRecommendedSchemeHexValues() {
      return Arrays.stream(values())
          .filter(scheme -> scheme.getTls13Policy() == Tls13Policy.LEGACY_DISALLOWED)
          .map(TlsSignatureSchemes::getHexValue)
          .collect(Collectors.joining(","));
    }

    /**
     * Resolves a TLS-1.3 signature scheme from the two-byte algorithm value logged in CertificateVerify.
     *
     * @param firstByte first logged hex byte
     * @param secondByte second logged hex byte
     * @return matching TLS-1.3 signature scheme, or throws if unknown
     */
    public static TlsSignatureSchemes fromAlgorithmBytes(String firstByte, String secondByte) {
      var tuple = "(0x%s,0x%s)".formatted(firstByte.toUpperCase(Locale.ROOT), secondByte.toUpperCase(Locale.ROOT));
      return Arrays.stream(values())
          .filter(scheme -> scheme.getHexValue().equalsIgnoreCase(tuple))
          .findFirst()
          .orElseThrow(() -> new AssertionError("Unsupported TLS 1.3 signature scheme: " + tuple));
    }

    /**
     * Returns the hash algorithm associated with this TLS-1.3 signature scheme.
     *
     * @return associated TLS hash algorithm, or {@link TlsHashAlgorithm#UNKNOWN} if it cannot be derived
     */
    public TlsHashAlgorithm getAssociatedHashAlgorithm() {
      var normalizedName = schemeName.toLowerCase(Locale.ROOT);
      if (normalizedName.endsWith("_sha1")) {
        return TlsHashAlgorithm.SHA1;
      }
      if (normalizedName.endsWith("_sha224")) {
        return TlsHashAlgorithm.SHA224;
      }
      if (normalizedName.endsWith("_sha256")) {
        return TlsHashAlgorithm.SHA256;
      }
      if (normalizedName.endsWith("_sha384")) {
        return TlsHashAlgorithm.SHA384;
      }
      if (normalizedName.endsWith("_sha512")) {
        return TlsHashAlgorithm.SHA512;
      }
      return TlsHashAlgorithm.UNKNOWN;
    }

    /**
     * Checks whether this TLS-1.3 signature scheme uses one of the provided hash algorithms.
     *
     * @param hashAlgorithms supported hash algorithms
     * @return {@code true} if the scheme name matches any provided hash algorithm
     */
    private boolean matchesAnyHash(Set<TlsHashAlgorithm> hashAlgorithms) {
      if (hashAlgorithms == null || hashAlgorithms.isEmpty()) {
        return false;
      }
      return hashAlgorithms.stream().anyMatch(this::matchesHash);
    }

    /**
     * Checks whether this TLS-1.3 signature scheme uses the provided hash algorithm.
     *
     * @param hashAlgorithm supported hash algorithm
     * @return {@code true} if the scheme name ends with the hash suffix
     */
    private boolean matchesHash(TlsHashAlgorithm hashAlgorithm) {
      if (hashAlgorithm == null || hashAlgorithm == TlsHashAlgorithm.UNKNOWN || hashAlgorithm == TlsHashAlgorithm.SUPPORTED_MIX) {
        return false;
      }
      return getAssociatedHashAlgorithm() == hashAlgorithm;
    }
  }

  /**
   * TLS 1.2 hash algorithm IDs used in signature_algorithms and ServerKeyExchange metadata.
   */
  public enum TlsHashAlgorithm {
    MD5(1, "0x01", "md5", false),
    SHA1(2, "0x02", "sha1", false),
    SHA224(3, "0x03", "sha224", false),
    SHA256(4, "0x04", "sha256", true),
    SHA384(5, "0x05", "sha384", true),
    SHA512(6, "0x06", "sha512", true),
    UNKNOWN(-1, "n/a", "unknown", false),
    SUPPORTED_MIX(-1, "n/a", "supported_mix", false);

    @Getter
    private final int value;
    @Getter
    private final String hexValue;
    @Getter
    private final String displayName;
    @Getter
    private final boolean supportedByPolicy;

    TlsHashAlgorithm(int value, String hexValue, String displayName, boolean supportedByPolicy) {
      this.value = value;
      this.hexValue = hexValue;
      this.displayName = displayName;
      this.supportedByPolicy = supportedByPolicy;
    }

    /**
     * Resolve enum by TLS 1.2 hash id.
     *
     * @param value TLS hash id from protocol metadata
     * @return matching enum or {@link #UNKNOWN}
     */
    public static TlsHashAlgorithm fromValue(int value) {
      return Arrays.stream(values())
          .filter(algorithm -> algorithm.value == value)
          .findFirst()
          .orElse(UNKNOWN);
    }

    /**
     * Resolve enum by textual hash name used in feature tables and logs.
     *
     * @param displayName the human-readable hash name to resolve
     * @return matching hash {@link TlsHashAlgorithm}, or {@link #UNKNOWN} if no match is found
     */
    public static TlsHashAlgorithm fromDisplayName(String displayName) {
      if (displayName == null || displayName.isBlank()) {
        return UNKNOWN;
      }

      String needle = displayName.trim();
      return java.util.Arrays.stream(values())
          .filter(g -> g.displayName.equalsIgnoreCase(needle))
          .findFirst()
          .orElse(UNKNOWN);
    }

    /**
     * Return all hash algorithms currently allowed by policy for TLS 1.2 signature usage.
     *
     * @return insertion-ordered set of policy-supported hash algorithms
     */
    public static LinkedHashSet<TlsHashAlgorithm> supportedByPolicy() {
      return Arrays.stream(values())
          .filter(TlsHashAlgorithm::isSupportedByPolicy)
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return all hash algorithms currently disallowed by policy for TLS 1.2 signature usage.
     *
     * @return insertion-ordered set of policy-disallowed hash algorithms
     */
    public static LinkedHashSet<TlsHashAlgorithm> unsupportedByPolicy() {
      return Arrays.stream(values())
          .filter(algorithm -> algorithm != UNKNOWN && algorithm != SUPPORTED_MIX && !algorithm.isSupportedByPolicy())
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return policy-supported hash names as expected in Gherkin data tables.
     *
     * @return set of enum names for policy-supported hash algorithms
     */
    public static Set<String> supportedByPolicyNames() {
      return supportedByPolicy().stream().map(Enum::name).collect(Collectors.toSet());
    }

    /**
     * Return policy-disallowed hash names as expected in Gherkin data tables.
     *
     * @return set of enum names for policy-disallowed hash algorithms
     */
    public static Set<String> unsupportedByPolicyNames() {
      return unsupportedByPolicy().stream().map(Enum::name).collect(Collectors.toSet());
    }
  }

  /**
   * TLS 1.2 signature algorithm IDs used in signature_algorithms and ServerKeyExchange metadata.
   */
  public enum TlsSignatureAlgorithm {
    RSA(1, "0x01", Policy.FORBIDDEN),
    DSA(2, "0x02", Policy.OPTIONAL),
    ECDSA(3, "0x03", Policy.OPTIONAL),
    UNKNOWN(-1, "n/a", Policy.NA);

    @lombok.Getter private final int value;
    @lombok.Getter private final String hexValue;
    @lombok.Getter private final Policy policy;

    TlsSignatureAlgorithm(int value, String hexValue, Policy policy) {
      this.value = value;
      this.hexValue = hexValue;
      this.policy = policy;
    }

    /**
     * Policy classification for TLS signature algorithms used when validating a ClientHello.
     *
     * <ul>
     *   <li>{@link #MANDATORY} – the signature algorithm must be offered/supported to comply with the policy.</li>
     *   <li>{@link #OPTIONAL} – the signature algorithm is permitted by policy but not required.</li>
     *   <li>{@link #FORBIDDEN} – the signature algorithm must not be offered; its presence is a policy violation.</li>
     *   <li>{@link #NA} – not applicable / unspecified (e.g., placeholder or unknown signature algorithm).</li>
     * </ul>
     */
    public enum Policy {
      MANDATORY,
      OPTIONAL,
      FORBIDDEN,
      NA
    }

    /**
     * Resolve enum by TLS 1.2 signature id.
     *
     * @param value TLS signature id from protocol metadata
     * @return matching enum or {@link #UNKNOWN}
     */
    public static TlsSignatureAlgorithm fromValue(int value) {
      return Arrays.stream(values())
          .filter(algorithm -> algorithm.value == value)
          .findFirst()
          .orElse(UNKNOWN);
    }

    /**
     * Returns all supported TLS 1.2 signature algorithms defined by {@link TlsSignatureAlgorithm}.
     *
     * @return an {@link List} of all supported {@link TlsSignatureAlgorithm} values
     */
    public static List<TlsSignatureAlgorithm> getSupportedSignatureAlgorithms() {
      return Arrays.stream(TlsSignatureAlgorithm.values())
          .filter(g -> g.getPolicy() == Policy.MANDATORY
              || g.getPolicy() == Policy.OPTIONAL)
          .collect(Collectors.toList());
    }

    /**
     * Returns all unsupported / forbidden TLS 1.2 signature algorithms defined by {@link TlsSignatureAlgorithm}.
     *
     * @return an {@link List} of all forbidden {@link TlsSignatureAlgorithm} values
     */
    public static List<TlsSignatureAlgorithm> getUnsupportedSignatureAlgorithms() {
      return Arrays.stream(TlsSignatureAlgorithm.values())
          .filter(g -> g.getPolicy() == Policy.FORBIDDEN)
          .collect(Collectors.toList());
    }

  }

  /**
   * TLS "supported_groups" (extension 0x000a) NamedGroup IDs with policy classification.
   */
  public enum TlsSupportedGroup {

    // Mandatory
    SECP256R1(0x0017, "secp256r1", Tls12Policy.MANDATORY, Tls13Policy.RECOMMENDED),
    SECP384R1(0x0018, "secp384r1", Tls12Policy.MANDATORY, Tls13Policy.RECOMMENDED),

    // Optional
    BRAINPOOLP256R1(0x001A, "brainpoolP256r1", Tls12Policy.OPTIONAL, Tls13Policy.OPTIONAL),
    BRAINPOOLP384R1(0x001B, "brainpoolP384r1", Tls12Policy.OPTIONAL, Tls13Policy.OPTIONAL),
    BRAINPOOLP512R1(0x001C, "brainpoolP512r1", Tls12Policy.OPTIONAL, Tls13Policy.OPTIONAL),

    // TLS 1.3 tool names for brainpool curves
    BRAINPOOLP256R1TLS13(0x001F, "brainpoolP256r1tls13", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    BRAINPOOLP384R1TLS13(0x0020, "brainpoolP384r1tls13", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    BRAINPOOLP512R1TLS13(0x0021, "brainpoolP512r1tls13", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),

    // Forbidden
    SECP192R1(0x0013, "secp192r1", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    SECP224R1(0x0015, "secp224r1", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    SECP521R1(0x0019, "secp521r1 (P-521)", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    SECP256K1(0x0016, "secp256k1", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),

    X25519(0x001D, "x25519", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    X448(0x001E, "x448", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),

    FFDHE2048(0x0100, "ffdhe2048", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    FFDHE3072(0x0101, "ffdhe3072", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    FFDHE4096(0x0102, "ffdhe4096", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    FFDHE6144(0x0103, "ffdhe6144", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),
    FFDHE8192(0x0104, "ffdhe8192", Tls12Policy.FORBIDDEN, Tls13Policy.FORBIDDEN),

    UNKNOWN(-1, "unknown", Tls12Policy.NA, Tls13Policy.NA),
    UNSUPPORTED_MIX(-1, "unsupported_mix", Tls12Policy.NA, Tls13Policy.NA);

    /**
     * TLS-1.2 policy classification for supported groups (NamedGroup IDs) used when validating a ClientHello.
     *
     * <ul>
     *   <li>{@link #MANDATORY} – the group must be offered/supported to comply with the policy.</li>
     *   <li>{@link #OPTIONAL} – the group is permitted by policy but not required.</li>
     *   <li>{@link #FORBIDDEN} – the group must not be offered; its presence is a policy violation.</li>
     *   <li>{@link #NA} – not applicable / unspecified (e.g., placeholder or unknown group).</li>
     * </ul>
     */
    public enum Tls12Policy {
      MANDATORY,
      OPTIONAL,
      FORBIDDEN,
      NA
    }

    /**
     * TLS-1.3-specific recommendation classification for supported_groups entries.
     */
    public enum Tls13Policy {
      RECOMMENDED,
      FORBIDDEN,
      OPTIONAL,
      NA
    }

    @lombok.Getter private final int value;
    @lombok.Getter private final String displayName;
    @lombok.Getter private final Tls12Policy tls12Policy;
    @lombok.Getter private final Tls13Policy tls13Policy;

    TlsSupportedGroup(int value, String displayName, Tls12Policy tls12Policy, Tls13Policy tls13Policy) {
      this.value = value;
      this.displayName = displayName;
      this.tls12Policy = tls12Policy;
      this.tls13Policy = tls13Policy;
    }

    /**
     * Resolves a {@link TlsSupportedGroup} from its numeric NamedGroup identifier.
     *
     * @param value numeric NamedGroup ID (typically an uint16 from protocol metadata)
     * @return matching {@link TlsSupportedGroup}, or {@link #UNKNOWN} if the value is not recognized
     */
    public static TlsSupportedGroup fromValue(int value) {
      return java.util.Arrays.stream(values())
          .filter(group -> group.value == value)
          .findFirst()
          .orElse(UNKNOWN);
    }

    /**
     * Resolves a {@link TlsSupportedGroup} from a hex-encoded NamedGroup identifier.
     *
     * @param hex hex-encoded NamedGroup ID (with or without {@code 0x} prefix)
     * @return matching {@link TlsSupportedGroup}, or {@link #UNKNOWN} for invalid/unknown inputs
     */
    public static TlsSupportedGroup fromHex(String hex) {
      if (hex == null || hex.isBlank()) {
        return UNKNOWN;
      }
      String s = hex.trim();
      if (s.startsWith("0x") || s.startsWith("0X")) {
        s = s.substring(2);
      }
      try {
        return fromValue(Integer.parseInt(s, 16));
      } catch (NumberFormatException e) {
        return UNKNOWN;
      }
    }

    /**
     * Resolves a {@link TlsSupportedGroup} by its human-readable display name.
     *
     * @param displayName the human-readable group name to resolve
     * @return matching {@link TlsSupportedGroup}, or {@link #UNKNOWN} if no match is found
     */
    public static TlsSupportedGroup fromDisplayName(String displayName) {
      if (displayName == null || displayName.isBlank()) {
        return UNKNOWN;
      }

      String needle = displayName.trim();
      if ("p256".equalsIgnoreCase(needle)) {
        return SECP256R1;
      }
      if ("p384".equalsIgnoreCase(needle)) {
        return SECP384R1;
      }
      return java.util.Arrays.stream(values())
          .filter(g -> g.displayName.equalsIgnoreCase(needle))
          .findFirst()
          .orElse(UNKNOWN);
    }

    /**
     * Builds a TLS {@code supported_groups} extension (type {@code 0x000a}) from the provided list of
     * {@link TlsSupportedGroup}.
     *
     * @param groups list of  {@link TlsSupportedGroup} groups to encode
     * @return {@code supported_groups} extension as a lowercase hex string (no whitespace)
     * @throws IllegalArgumentException if {@code groups} is {@code null} or empty
     */
    public static String buildSupportedGroupsExtension(List<TlsSupportedGroup> groups) {
      if (groups == null || groups.isEmpty()) {
        throw new IllegalArgumentException("groups must not be null/empty");
      }

      int listLenBytes = groups.size() * 2;      // each group is u16
      int extLenBytes  = 2 + listLenBytes;       // u16 listLen + list

      StringBuilder sb = new StringBuilder();
      sb.append("000a");                         // extension type supported_groups
      sb.append(u16(extLenBytes));               // extension length
      sb.append(u16(listLenBytes));              // list length
      for (TlsSupportedGroup g : groups) {
        sb.append(u16(g.getValue()));            // group id
      }
      return sb.toString().toLowerCase();
    }

    /**
     * Formats an unsigned 16-bit value as a four-digit lowercase hex string.
     *
     * @param v value in range 0..65535
     * @return hex string representation (e.g. {@code 000a})
     */
    private static String u16(int v) {
      return String.format("%04x", v & 0xFFFF);
    }

    /**
     * Returns all groups that are forbidden by policy.
     *
     * @return a list of policy-forbidden groups, in enum order
     */
    public static List<TlsSupportedGroup> forbiddenGroups() {
      return Arrays.stream(TlsSupportedGroup.values())
          .filter(g -> g.getTls12Policy() == TlsSupportedGroup.Tls12Policy.FORBIDDEN)
          .collect(Collectors.toList());
    }

    /**
     * Returns all TLS-1.3 supported groups that are forbidden by the TLS-1.3 policy.
     *
     * @return a list of TLS-1.3-policy-forbidden groups, in enum order
     */
    public static List<TlsSupportedGroup> forbiddenGroupsForTls13() {
      return Arrays.stream(TlsSupportedGroup.values())
          .filter(g -> g.getTls13Policy() == Tls13Policy.FORBIDDEN)
          .collect(Collectors.toList());
    }

    /**
     * Returns all supported groups that are permitted by policy.
     *
     * @return a list of policy-allowed supported groups (mandatory + optional), in enum order
     */
    public static List<TlsSupportedGroup> allowedGroups() {
      return Arrays.stream(TlsSupportedGroup.values())
          .filter(g -> g.getTls12Policy() == TlsSupportedGroup.Tls12Policy.MANDATORY
              || g.getTls12Policy() == TlsSupportedGroup.Tls12Policy.OPTIONAL)
          .collect(Collectors.toList());
    }

    /**
     * Returns the TLS-1.3 supported_groups names in the required wire-name form and order.
     *
     * @return comma-separated TLS-1.3 supported_groups names
     */
    public static String tls13SupportedGroups() {
      return Arrays.stream(TlsSupportedGroup.values())
          .filter(g -> g.getTls13Policy() == Tls13Policy.RECOMMENDED
              || g.getTls13Policy() == Tls13Policy.OPTIONAL)
          .map(TlsSupportedGroup::getDisplayName)
          .collect(Collectors.joining(","));
    }

    /**
     * Returns the TLS-1.3 supported_groups value for the provided groups in wire-name form.
     *
     * @param groups groups to encode for tls-test-tool configuration
     * @return comma-separated TLS-1.3 supported_groups names
     */
    public static String tls13SupportedGroupsValue(List<TlsSupportedGroup> groups) {
      if (groups == null || groups.isEmpty()) {
        throw new IllegalArgumentException("groups must not be null/empty");
      }
      return groups.stream()
          .map(TlsSupportedGroup::getDisplayName)
          .collect(Collectors.joining(","));
    }

  }

  /**
   * TLS versions.
   */
  public enum TlsVersion {
    TLS_1_2("TLS 1.2"),
    TLS_1_3("TLS 1.3");

    @Getter
    private final String displayName;

    TlsVersion(String displayName) {
      this.displayName = displayName;
    }
  }

  /**
   * Mandatory and optional TLS cipher suites.
   */
  public enum TlsCipherSuite {
    // Mandatory
    ECDHE_ECDSA_AES_128_GCM_SHA256("ecdhe_ecdsa_aes_128_gcm_sha256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "(0xC0,0x2B)", TlsVersion.TLS_1_2, true),
    ECDHE_ECDSA_AES_256_GCM_SHA384("ecdhe_ecdsa_aes_256_gcm_sha384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "(0xC0,0x2C)", TlsVersion.TLS_1_2, true),
    // Optional (TR-02102-2, Abschnitt 3.3.1.1, Tabelle 1)
    ECDHE_ECDSA_AES_128_CBC_SHA256("ecdhe_ecdsa_aes_128_cbc_sha256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "(0xC0,0x23)", TlsVersion.TLS_1_2, false),
    ECDHE_ECDSA_AES_256_CBC_SHA384("ecdhe_ecdsa_aes_256_cbc_sha384", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "(0xC0,0x24)", TlsVersion.TLS_1_2, false),
    ECDHE_ECDSA_AES_128_CCM("ecdhe_ecdsa_aes_128_ccm", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "(0xC0,0xAC)", TlsVersion.TLS_1_2, false),
    ECDHE_ECDSA_AES_256_CCM("ecdhe_ecdsa_aes_256_ccm", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "(0xC0,0xAD)", TlsVersion.TLS_1_2, false),
    ECDHE_RSA_AES_128_GCM_SHA256("ecdhe_rsa_aes_128_gcm_sha256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "(0xC0,0x2F)", TlsVersion.TLS_1_2, false),
    ECDHE_RSA_AES_256_GCM_SHA384("ecdhe_rsa_aes_256_gcm_sha384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "(0xC0,0x30)", TlsVersion.TLS_1_2, false),
    ECDHE_RSA_AES_128_CBC_SHA256("ecdhe_rsa_aes_128_cbc_sha256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "(0xC0,0x27)", TlsVersion.TLS_1_2, false),
    ECDHE_RSA_AES_256_CBC_SHA384("ecdhe_rsa_aes_256_cbc_sha384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "(0xC0,0x28)", TlsVersion.TLS_1_2, false),
    DHE_DSS_AES_128_CBC_SHA256("dhe_dss_aes_128_cbc_sha256", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "(0x00,0x40)", TlsVersion.TLS_1_2, false),
    DHE_DSS_AES_256_CBC_SHA256("dhe_dss_aes_256_cbc_sha256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "(0x00,0x6A)", TlsVersion.TLS_1_2, false),
    DHE_DSS_AES_128_GCM_SHA256("dhe_dss_aes_128_gcm_sha256", "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "(0x00,0xA2)", TlsVersion.TLS_1_2, false),
    DHE_DSS_AES_256_GCM_SHA384("dhe_dss_aes_256_gcm_sha384", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "(0x00,0xA3)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_128_CBC_SHA256("dhe_rsa_aes_128_cbc_sha256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "(0x00,0x67)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_256_CBC_SHA256("dhe_rsa_aes_256_cbc_sha256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "(0x00,0x6B)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_128_GCM_SHA256("dhe_rsa_aes_128_gcm_sha256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "(0x00,0x9E)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_256_GCM_SHA384("dhe_rsa_aes_256_gcm_sha384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "(0x00,0x9F)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_128_CCM("dhe_rsa_aes_128_ccm", "TLS_DHE_RSA_WITH_AES_128_CCM", "(0xC0,0x9E)", TlsVersion.TLS_1_2, false),
    DHE_RSA_AES_256_CCM("dhe_rsa_aes_256_ccm", "TLS_DHE_RSA_WITH_AES_256_CCM", "(0xC0,0x9F)", TlsVersion.TLS_1_2, false),
    // Mandatory
    AES_128_GCM_SHA256("aes_128_gcm_sha256", "TLS_AES_128_GCM_SHA256", "(0x13,0x01)", TlsVersion.TLS_1_3, true),
    AES_256_GCM_SHA384("aes_256_gcm_sha384", "TLS_AES_256_GCM_SHA384", "(0x13,0x02)", TlsVersion.TLS_1_3, true),
    // Optional (TLS 1.3)
    CHACHA20_POLY1305_SHA256("chacha20_poly1305_sha256", "TLS_CHACHA20_POLY1305_SHA256", "(0x13,0x03)", TlsVersion.TLS_1_3, false),
    AES_128_CCM_SHA256("aes_128_ccm_sha256", "TLS_AES_128_CCM_SHA256", "(0x13,0x04)", TlsVersion.TLS_1_3, false),
    AES_128_CCM_8_SHA256("aes_128_ccm_8_sha256", "TLS_AES_128_CCM_8_SHA256", "(0x13,0x05)", TlsVersion.TLS_1_3, false),
    // The empty renegotiation cipher suite is added automatically by clients that support secure renegotiation
    EMPTY_RENEGOTIATION_INFO_SCSV("empty_renegotiation_info_scsv", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "(0x00,0xFF)", TlsVersion.TLS_1_2, false);

    @Getter
    private final String cipherSuiteId;
    @Getter
    private final String cipherSuiteName;
    @Getter
    private final String tlsTestToolCipherSuiteValue;
    @Getter
    private final TlsVersion tlsVersion;
    @Getter
    private final Boolean isMandatory;

    TlsCipherSuite(String cipherSuiteId, String cipherSuiteName, String tlsTestToolCipherSuiteValue, TlsVersion tlsVersion,
        Boolean isMandatory) {
      this.cipherSuiteId = cipherSuiteId;
      this.cipherSuiteName = cipherSuiteName;
      this.tlsTestToolCipherSuiteValue = tlsTestToolCipherSuiteValue;
      this.tlsVersion = tlsVersion;
      this.isMandatory = isMandatory;
    }

    /**
     * Resolve enum by readable cipher suite profile token used in feature files.
     *
     * @param cipherSuiteId profile token
     * @return matching profile
     */
    public static TlsCipherSuite fromCipherSuiteId(String cipherSuiteId) {
      return Arrays.stream(values())
          .filter(profile -> profile.cipherSuiteId.equals(cipherSuiteId))
          .findFirst()
          .orElseThrow(() -> new AssertionError("Unsupported ciphersuite : " + cipherSuiteId));
    }

    /**
     * Return all supported TLS 1.2 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> supportedTls12CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs != EMPTY_RENEGOTIATION_INFO_SCSV)
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_2)
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return all supported TLS 1.2 Cipher Suites without optional from TR-02102-2, Abschnitt 3.3.1 .
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> supportedTls12CipherSuitesWithoutOptional() {
      return Arrays.stream(values())
          .filter(cs -> cs != EMPTY_RENEGOTIATION_INFO_SCSV)
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_2)
          .filter(cs -> Boolean.TRUE.equals(cs.getIsMandatory()))
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return all supported TLS 1.3 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> supportedTls13CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_3)
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return all supported TLS 1.3 Cipher Suites without optional from TR-02102-2, Abschnitt 3.3.1 .     *
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> supportedTls13CipherSuitesWithoutOptional() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_3)
          .filter(cs -> Boolean.TRUE.equals(cs.getIsMandatory()))
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return optional TLS 1.2 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> optionalTls12CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_2)
          .filter(cs -> !Boolean.TRUE.equals(cs.getIsMandatory()))
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return optional TLS 1.3 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> optionalTls13CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_3)
          .filter(cs -> !Boolean.TRUE.equals(cs.getIsMandatory()))
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return mandatory TLS 1.2 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> mandatoryTls12CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_2)
          .filter(TlsCipherSuite::getIsMandatory)
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Return mandatory TLS 1.3 Cipher Suites.
     *
     * @return insertion-ordered set of policy-supported cipher suites
     */
    public static LinkedHashSet<TlsCipherSuite> mandatoryTls13CipherSuites() {
      return Arrays.stream(values())
          .filter(cs -> cs.getTlsVersion() == TlsVersion.TLS_1_3)
          .filter(TlsCipherSuite::getIsMandatory)
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }

  }

  /**
   * Certificate and key files shipped with the TLS test tool fixture.
   */
  public enum TlsServerCertificates {
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_PRIVATE_KEY("zeta_tls_test_tool_server_ecdsa_private_key", "ecdsa/zeta-tls-test-tool-server.privkey.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_DIFFERENT_CN_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_different_cn_certificate", "ecdsa/zeta-tls-test-tool-server_evil_cn.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_DIFFERENT_CN_SAN_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate", "ecdsa/zeta-tls-test-tool-server_evil_cn_san.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_DIFFERENT_SAN_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_different_san_certificate", "ecdsa/zeta-tls-test-tool-server_evil_san.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_GOOD_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_good_certificate", "ecdsa/zeta-tls-test-tool-server_good.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_EXPIRED_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_expired_certificate", "ecdsa/zeta-tls-test-tool-server_expired.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_NOT_YET_VALID_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate", "ecdsa/zeta-tls-test-tool-server_not_yet_valid.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_DIFFERENT_CA_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_different_ca_certificate", "ecdsa/zeta-tls-test-tool-server_no_chain.pem"),
    ZETA_TLS_TEST_TOOL_SERVER_ECDSA_OCSP_RESPONDER_CERTIFICATE("zeta_tls_test_tool_server_ecdsa_ocsp_responder_certificate", "ecdsa/zeta-tls-test-tool-server_ocsp.pem");

    @Getter
    private final String certificateId;
    @Getter
    private final String relativePath;

    TlsServerCertificates(String certificateId, String relativePath) {
      this.certificateId = certificateId;
      this.relativePath = relativePath;
    }

    /**
     * Resolve enum by readable certificate token used in feature files.
     *
     * @param certificateId profile token
     * @return matching profile
     */
    public static TlsServerCertificates fromCertificateId(String certificateId) {
      return Arrays.stream(values())
          .filter(profile -> profile.certificateId.equals(certificateId))
          .findFirst()
          .orElseThrow(() -> new AssertionError("Unsupported server certificate: " + certificateId));
    }

    /**
     * Returns the private key enum entry for a given certificate enum entry.
     *
     * @param certificate certificate enum entry
     * @return private key enum entry matching the provided certificate
     */
    public static TlsServerCertificates getPrivateKeyForCertificate(TlsServerCertificates certificate) {
      if (certificate == null) {
        throw new AssertionError("The server certificate is empty or null.");
      }
      String enumName = certificate.name();
      if (enumName.contains("_ECDSA_") && enumName.endsWith("_CERTIFICATE")) {
        return ZETA_TLS_TEST_TOOL_SERVER_ECDSA_PRIVATE_KEY;
      }
      throw new AssertionError("Unsupported certificate for private key mapping: " + enumName);
    }
  }

  /**
   * Expected TLS handshake result tokens used in feature files.
   */
  public enum TlsHandshakeExpectation {
    ERFOLGREICH("erfolgreich", "successful"),
    NICHT_ERFOLGREICH("nicht erfolgreich", "not successful");

    private final String deValue;
    private final String enValue;

    TlsHandshakeExpectation(String deValue, String enValue) {
      this.deValue = deValue;
      this.enValue = enValue;
    }

    /**
     * Resolve enum by textual expectation used in feature files.
     *
     * @param value expectation token
     * @return matching handshake expectation
     */
    public static TlsHandshakeExpectation fromValue(String value) {
      return Arrays.stream(values())
          .filter(expectation -> expectation.deValue.equals(value) || expectation.enValue.equals(value))
          .findFirst()
          .orElseThrow(() -> new AssertionError("Unsupported TLS handshake expectation: " + value));
    }
  }

  /**
   * Inclusive-exclusive line range that represents one selected handshake phase in TLS logs.
   */
  private record TlsLogPhase(int startInclusive, int endExclusive) {

  }

  /**
   * Extracts the {@code supported_groups} (extension {@code 0x000A}) list from a TLS ClientHello
   * contained in the given tool log and returns it as a list of {@link TlsSupportedGroup}.
   *
   * @param fullLog complete TLS test tool log output containing {@code ClientHello.extensions=...}
   * @return list of extracted supported groups in the order they appear in the ClientHello;
   *         empty list if not present or malformed
   * @throws AssertionError if {@code fullLog} is {@code null/blank} or if no {@code ClientHello.extensions}
   *                        section is present in the log
   */
  private static List<TlsSupportedGroup> extractSupportedGroupsHex(String fullLog) {
    byte[] sg = findClientHelloExtensionData(fullLog, TLS_EXTENSION_SUPPORTED_GROUPS);
    if (sg == null || sg.length < 2) {
      return List.of();
    }

    int listLen = u16(sg, 0);
    if (2 + listLen > sg.length) {
      return List.of();
    }

    List<TlsSupportedGroup> groups = new ArrayList<>();
    for (int i = 2; i + 1 < 2 + listLen; i += 2) {
      groups.add(TlsSupportedGroup.fromHex(String.format("%04x", u16(sg, i))));
    }
    return groups;
  }

  /**
   * Extracts the {@code key_share} (extension {@code 0x0033}) group list from a TLS ClientHello
   * contained in the given tool log and returns it as a list of {@link TlsSupportedGroup}.
   *
   * @param fullLog complete TLS test tool log output containing {@code ClientHello.extensions=...}
   * @return list of extracted key_share groups in the order they appear in the ClientHello;
   *         empty list if not present or malformed
   * @throws AssertionError if {@code fullLog} is {@code null/blank} or if no {@code ClientHello.extensions}
   *                        section is present in the log
   */
  private static List<TlsSupportedGroup> extractClientKeyShareGroups(String fullLog) {
    byte[] keyShare = findClientHelloExtensionData(fullLog, TLS_EXTENSION_KEY_SHARE, true);
    if (keyShare == null || keyShare.length < 2) {
      return List.of();
    }

    int clientSharesLength = u16(keyShare, 0);
    if (2 + clientSharesLength > keyShare.length) {
      return List.of();
    }

    List<TlsSupportedGroup> groups = new ArrayList<>();
    int offset = 2;
    int end = 2 + clientSharesLength;
    while (offset + 4 <= end) {
      int groupId = u16(keyShare, offset);
      int keyExchangeLength = u16(keyShare, offset + 2);
      int nextOffset = offset + 4 + keyExchangeLength;
      if (nextOffset > end) {
        return List.of();
      }

      groups.add(TlsSupportedGroup.fromValue(groupId));
      offset = nextOffset;
    }

    if (offset != end && keyShare.length == end) {
      return List.of();
    }
    if (keyShare.length > end) {
      addRecoverableKeyShareGroups(groups, keyShare);
    }
    return groups;
  }

  /**
   * Adds key_share groups from trailing bytes when a log line contains more key_share data than the declared extension length.
   *
   * @param groups already parsed key_share groups
   * @param keyShare key_share extension payload bytes
   */
  private static void addRecoverableKeyShareGroups(List<TlsSupportedGroup> groups, byte[] keyShare) {
    for (var offset = 2; offset + 4 <= keyShare.length; offset++) {
      var group = TlsSupportedGroup.fromValue(u16(keyShare, offset));
      var keyExchangeLength = u16(keyShare, offset + 2);
      if (group == TlsSupportedGroup.UNKNOWN || groups.contains(group)) {
        continue;
      }
      if (offset + 4 + keyExchangeLength <= keyShare.length) {
        groups.add(group);
      }
    }
  }

  /**
   * Extracts the TLS-1.3 {@code signature_algorithms} extension values from a TLS ClientHello.
   *
   * @param fullLog complete TLS test tool log output containing {@code ClientHello.extensions=...}
   * @return list of extracted TLS-1.3 signature schemes in ClientHello order; empty list if not present or malformed
   * @throws AssertionError if {@code fullLog} is {@code null/blank} or if no {@code ClientHello.extensions}
   *                        section is present in the log
   */
  private static List<TlsSignatureSchemes> extractTls13SignatureSchemes(String fullLog) {
    byte[] signatureAlgorithms = findClientHelloExtensionData(fullLog, TLS_EXTENSION_SIGNATURE_ALGORITHMS, true);
    if (signatureAlgorithms == null || signatureAlgorithms.length < 2) {
      return List.of();
    }

    int listLen = u16(signatureAlgorithms, 0);
    int listEnd = Math.min(2 + listLen, signatureAlgorithms.length);

    List<TlsSignatureSchemes> schemes = new ArrayList<>();
    for (int i = 2; i + 1 < listEnd; i += 2) {
      var firstByte = String.format("%02X", signatureAlgorithms[i] & 0xFF);
      var secondByte = String.format("%02X", signatureAlgorithms[i + 1] & 0xFF);
      schemes.add(TlsSignatureSchemes.fromAlgorithmBytes(firstByte, secondByte));
    }
    return schemes;
  }

  /**
   * Extracts the {@code signature_algorithms} (extension {@code 0x000D}) list from a TLS ClientHello
   * contained in the given tool log and returns signature algorithms as a list of {@link TlsSignatureAlgorithm}.
   *
   * @param fullLog complete TLS test tool log output containing {@code ClientHello.extensions=...}
   * @return list of extracted signature algorithms in the order they appear in the ClientHello;
   *         empty list if the extension payload is malformed
   * @throws AssertionError if {@code fullLog} is {@code null/blank} or if no {@code ClientHello.extensions}
   *                        section is present in the log, or if no {@code signature_algorithms}
   *                        extension is present in the extracted extensions block
   */
  private static List<TlsSignatureAlgorithm> extractSignatureAlgorithmsHex(String fullLog) {
    byte[] signatureAlgorithms = findClientHelloExtensionData(fullLog, TLS_EXTENSION_SIGNATURE_ALGORITHMS, true);
    if (signatureAlgorithms == null || signatureAlgorithms.length < 2) {
      throw new AssertionError("signature_algorithms not present in the logs.");
    }

    int listLen = u16(signatureAlgorithms, 0);
    int listEnd = Math.min(2 + listLen, signatureAlgorithms.length);

    List<TlsSignatureAlgorithm> algorithms = new ArrayList<>();
    for (int i = 2; i + 1 < listEnd; i += 2) {
      int signatureAlgorithmId = signatureAlgorithms[i + 1] & 0xFF;
      algorithms.add(TlsSignatureAlgorithm.fromValue(signatureAlgorithmId));
    }
    return algorithms;
  }

  /**
   * Checks whether the ClientHello contains the supported_versions extension with TLS 1.3 (0x0304).
   *
   * @param fullLog complete TLS test tool log output containing {@code ClientHello.extensions=...}
   * @return {@code true} if TLS 1.3 is advertised in supported_versions, otherwise {@code false}
   * @throws AssertionError if {@code fullLog} is {@code null/blank} or if no {@code ClientHello.extensions}
   *                        section is present in the log
   */
  private static boolean clientHelloSignalsTls13Support(String fullLog) {
    byte[] supportedVersions = findClientHelloExtensionData(fullLog, TLS_EXTENSION_SUPPORTED_VERSIONS);
    if (supportedVersions == null || supportedVersions.length < 3) {
      return false;
    }

    int listLen = supportedVersions[0] & 0xFF;
    if (1 + listLen > supportedVersions.length) {
      return false;
    }

    for (int i = 1; i + 1 < 1 + listLen; i += 2) {
      if (u16(supportedVersions, i) == 0x0304) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extracts the hex payload after {@code ClientHello.extensions=} from one physical log line.
   *
   * @param line TLS log line
   * @return whitespace-separated extension bytes, or {@code null} if the marker is absent
   */
  private static String extractClientHelloExtensionsHexFromLine(String line) {
    var matcher = CLIENT_HELLO_EXTENSIONS_LINE_PATTERN.matcher(line);
    if (!matcher.find()) {
      return null;
    }
    var extensionBytes = matcher.group(1);
    return extensionBytes == null ? "" : extensionBytes.trim();
  }

  /**
   * Finds a specific extension payload in the logged ClientHello extension blocks.
   *
   * @param fullLog complete TLS test tool log output
   * @param wantedType extension type to locate
   * @return extension payload, or {@code null} if the extension is absent or malformed
   */
  private static byte[] findClientHelloExtensionData(String fullLog, int wantedType) {
    return findClientHelloExtensionData(fullLog, wantedType, false);
  }

  /**
   * Finds a specific extension payload in the logged ClientHello extension blocks.
   *
   * @param fullLog complete TLS test tool log output
   * @param wantedType extension type to locate
   * @param includeTrailingBytes whether payload extraction should include bytes after the declared extension length
   * @return extension payload, or {@code null} if the extension is absent or malformed
   */
  private static byte[] findClientHelloExtensionData(String fullLog, int wantedType, boolean includeTrailingBytes) {
    if (fullLog == null || fullLog.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }

    var clientHelloExtensionsFound = false;
    for (var line : fullLog.split("\\R")) {
      var extensionBytes = extractClientHelloExtensionsHexFromLine(line);
      if (extensionBytes == null) {
        continue;
      }
      clientHelloExtensionsFound = true;
      var extensionData = findExtensionData(parseHexBytesSafely(extensionBytes), wantedType, includeTrailingBytes);
      if (extensionData != null) {
        return extensionData;
      }
    }

    if (!clientHelloExtensionsFound) {
      throw new AssertionError("Client hello extension not present in the logs.");
    }
    return null;
  }

  /**
   * Parses hex bytes and returns an empty array when the hex payload is malformed.
   *
   * @param hexWithSpaces whitespace-separated hex bytes
   * @return parsed bytes, or an empty array if parsing fails
   */
  private static byte[] parseHexBytesSafely(String hexWithSpaces) {
    if (hexWithSpaces == null || hexWithSpaces.isBlank()) {
      return new byte[0];
    }
    try {
      return parseHexBytes(hexWithSpaces);
    } catch (NumberFormatException e) {
      return new byte[0];
    }
  }

  /**
   * Parses a whitespace-separated hex string into a byte array.
   *
   * @param hexWithSpaces whitespace-separated hex bytes (e.g., {@code "c0 2f 00 ff"})
   * @return parsed bytes in the same order as provided
   * @throws NullPointerException if {@code hexWithSpaces} is {@code null}
   * @throws NumberFormatException if any token is not valid hexadecimal
   */
  private static byte[] parseHexBytes(String hexWithSpaces) {
    var text = hexWithSpaces.trim();
    if (text.isEmpty()) {
      return new byte[0];
    }
    String normalized = text.replaceAll("\\s+", "");
    try {
      return Hex.decodeHex(normalized);
    } catch (DecoderException e) {
      NumberFormatException ex = new NumberFormatException("Invalid hex token");
      ex.initCause(e);
      throw ex;
    }
  }

  /**
   * Finds and returns the payload (data) of a specific TLS ClientHello extension.
   *
   * @param extensions the raw ClientHello extensions block (concatenated extensions)
   * @param wantedType the extension type to locate (e.g., {@code 0x000A} for supported_groups)
   * @return a new byte array containing the extension payload, or {@code null} if not found or malformed
   */
  private static byte[] findExtensionData(byte[] extensions, int wantedType) {
    return findExtensionData(extensions, wantedType, false);
  }

  /**
   * Finds and returns the payload (data) of a specific TLS ClientHello extension.
   *
   * @param extensions the raw ClientHello extensions block (concatenated extensions)
   * @param wantedType the extension type to locate (e.g., {@code 0x000A} for supported_groups)
   * @param includeTrailingBytes whether returned payload should include the remaining bytes after the extension header,
   *                             including bytes after the declared extension length or truncated logged payloads
   * @return a new byte array containing the extension payload, or {@code null} if not found or malformed
   */
  private static byte[] findExtensionData(byte[] extensions, int wantedType, boolean includeTrailingBytes) {
    int i = 0;
    while (i + 4 <= extensions.length) {
      int type = u16(extensions, i);
      int len  = u16(extensions, i + 2);
      int dataStart = i + 4;
      int dataEnd = dataStart + len;

      if (type == wantedType) {
        if (includeTrailingBytes) {
          return Arrays.copyOfRange(extensions, dataStart, extensions.length);
        }
        if (dataEnd > extensions.length) {
          return null; // malformed
        }
        return Arrays.copyOfRange(extensions, dataStart, dataEnd);
      }
      if (dataEnd > extensions.length) {
        return null; // malformed
      }

      i = dataEnd;
    }
    return null;
  }

  /**
   * Reads an unsigned 16-bit big-endian value from the provided byte array.
   *
   * @param b source byte array
   * @param off start offset of the 2-byte value
   * @return decoded value in range 0..65535
   */
  private static int u16(byte[] b, int off) {
    return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
  }

  /**
   * Supported TLS stack / crypto provider implementations.
   */
  private enum TlsLibrary {

    /** The mbed TLS library. */
    MBED_TLS("mbed TLS"),

    /** The OpenSSL library. */
    OPENSSL("OpenSSL");

    private final String displayName;

    TlsLibrary(String displayName) {
      this.displayName = displayName;
    }

    /**
     * Returns the human-readable display name of the TLS library.
     *
     * @return display name (e.g. {@code "mbed TLS"} or {@code "OpenSSL"})
     */
    public String getDisplayName() {
      return displayName;
    }

  }

  /**
   * Indicates the TLS endpoint role in a handshake/test scenario.
   *
   * <p>Use {@link #CLIENT} for the side initiating the TLS connection (sending the ClientHello),
   * and {@link #SERVER} for the side accepting the connection (responding with the ServerHello).
   */
  @Getter
  private enum TlsEndpointRole {

    /** Initiates the TLS connection and sends the ClientHello. */
    CLIENT("client"),

    /** Accepts the TLS connection and responds with the ServerHello. */
    SERVER("server");

    private final String displayName;

    TlsEndpointRole(String displayName) {
      this.displayName = displayName;
    }

  }

  /**
   * Checks whether the TLS log contains a successful handshake completion message
   * <em>after</em> a renegotiation has been initiated.
   *
   * @param fullLog the complete TLS log as a single string
   * @return {@code true} if {@code FINISHED_MARKER} appears after {@code RENEG_MARKER}; otherwise {@code false}
   */
  private static boolean hasFinishedAfterRenegotiation(String fullLog) {
    if (fullLog == null || fullLog.isBlank()) {
      throw new AssertionError("The TLS log is empty or null.");
    }

    int renegIdx = fullLog.indexOf(RENEG_MARKER);
    if (renegIdx < 0) {
      return false;
    }

    int finishedIdx = fullLog.indexOf(FINISHED_MARKER, renegIdx + RENEG_MARKER.length());
    return finishedIdx >= 0;
  }

}
