#
# #%L
# ZETA Testsuite
# %%
# (C) achelos GmbH, 2025, licensed for gematik GmbH
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
# #L%
#

#language:de

@UseCase_TLS_02
@no_proxy
Funktionalität: TLS-Konformität ZETA Client und ZETA Native Client

  @A_18464
  @GS-A_5542
  @TA_A_18464_02
  @TA_GS-A_5542_03
  @MASVS-CRYPTO
  @MASVS-NETWORK
  Szenariogrundriss: TLS-Verbindungen - <client_name> - TLS 1.1 darf nicht unterstützt werden.
    Gegeben sei die TlsTestTool-Server-Konfigurationsdaten wurden nur für TLS 1.1 erstellt
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und die ClientHello-TLS-Version ist 1.2
    # 46 in hexadezimal entspricht 70 in dezimal und ist der Alert Code für TLS Protocol Version Failure.
    Und akzeptiert der ZETA Client das ServerHello nicht und sendet eine Alert Nachricht mit Description Id "46"

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @GS-A_5526
  @TA_GS-A_5526_02
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - TLS-Renegotiation-Indication-Extension.
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Und der ClientHello-Record enthält TLS_EMPTY_RENEGOTIATION_INFO_SCSV oder eine leere renegotiation_info extension

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @GS-A_5526
  @TA_GS-A_5526_02
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - TLS-Renegotiation wird RFC-5746-konform verarbeitet.
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten mit HelloRequest für eine der unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Und wird die TLS-Handshake-renegotiation gestartet
    Und ist die TLS-Handshake-renegotiation RFC-5746-konform erfolgreich oder wird mit no_renegotiation oder handshake_failure abgelehnt

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_21275-01
  @TA_A_21275-01_05
  @TA_A_21275-01_07
  @TA_A_21275-01_08
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - zulässige Hashfunktionen bei Signaturen im TLS-Handshake - mindestens SHA-256 unterstützen
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für den Hash-Algorithmus "<hash_algorithm>"
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake <handshake_erwartung>
    # supported_mix: sha256, sha384, sha512
    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | hash_algorithm | handshake_erwartung | client_name | hello_path                |
      | sha1           | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |
      | sha224         | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |
      | supported_mix  | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | hash_algorithm | handshake_erwartung | client_name        | hello_path                      |
      | sha1           | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | sha224         | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | supported_mix  | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_21275-01
  @TA_A_21275-01_05
  @TA_A_21275-01_07
  @TA_A_21275-01_08
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - Signature-Schemes.
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und bietet der ClientHello nur die unterstützten Signature-Schemes an

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_08
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - es werden keine TLS-1.2-Cipher-Suiten außerhalb der nach TR-02102-2 zulässigen Menge angeboten.
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und der ClientHello-Record enthält nur Cipher-Suiten aus TR-02102-2, Abschnitt 3.3.1 Tabelle 1

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_08
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - es werden keine optionalen TLS-1.2-Cipher-Suiten aus TR-02102-2 zulässigen Menge angeboten.
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und der ClientHello-Record enthält keine optionalen Cipher-Suiten aus TR-02102-2, Abschnitt 3.3.1 Tabelle 1

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_07
  @TA_A_28868_10
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - elliptische Kurven - Negativtest.
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und bietet der ClientHello nur die unterstützten Kurven an

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_07
  @TA_A_28868_10
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - elliptische Kurven.
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und bietet der ClientHello nur die unterstützten Kurven an
    Und ist einer die unterstützten Kurven ist in der Client-Key-Share verwendet

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_07
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - elliptische Kurven - Positivtest.
    # Profile:
    # p256: secp256r1 (0017)
    # p384: secp384r1 (0018)
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützte Gruppe "<supported_group>"
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake <handshake_erwartung>
    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | supported_group | handshake_erwartung | client_name | hello_path                |
      | p256            | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |
      | p384            | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | supported_group | handshake_erwartung | client_name        | hello_path                      |
      | p256            | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | p384            | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_06
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - als Cipher-Suite MÜSSEN TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 und TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 unterstützt werden.
    # Profile:
    # ecdhe_ecdsa_aes_128_gcm_sha256 -> TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC0,0x2B)
    # ecdhe_ecdsa_aes_256_gcm_sha384 -> TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC0,0x2C)
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für das Cipher-Suite-Profil <ciphersuite_profil>
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | ciphersuite_profil             | client_name | hello_path                |
      | ecdhe_ecdsa_aes_128_gcm_sha256 | ZETA Client | ${paths.client.helloZeta} |
      | ecdhe_ecdsa_aes_256_gcm_sha384 | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | ciphersuite_profil             | client_name        | hello_path                      |
      | ecdhe_ecdsa_aes_128_gcm_sha256 | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | ecdhe_ecdsa_aes_256_gcm_sha384 | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_28868
  @TA_A_28868_09
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - bei TLS 1.3 MÜSSEN TLS_AES_128_GCM_SHA256 und TLS_AES_256_GCM_SHA384 unterstützt werden.
    # Profile:
    # aes_128_gcm_sha256 -> TLS_AES_128_GCM_SHA256 (0x13,0x01)
    # aes_256_gcm_sha384 -> TLS_AES_256_GCM_SHA384 (0x13,0x02)
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für das Cipher-Suite-Profil <ciphersuite_profil>
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und der ClientHello-Record signalisiert TLS 1.3 Unterstützung oder das Szenario wird übersprungen
    Und ist der TLS-Handshake erfolgreich
    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | ciphersuite_profil | client_name | hello_path                |
      | aes_128_gcm_sha256 | ZETA Client | ${paths.client.helloZeta} |
      | aes_256_gcm_sha384 | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | ciphersuite_profil | client_name        | hello_path                      |
      | aes_128_gcm_sha256 | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | aes_256_gcm_sha384 | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - RSA-Signaturalgorithmen dürfen für TLS 1.2 nicht unterstützt werden
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und bietet der ClientHello keine nicht unterstützten Signaturalgorithmen an

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - RSA-Signaturalgorithmen dürfen für TLS 1.3 nicht unterstützt werden
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und bietet der ClientHello keine nicht unterstützten RSA TLS 1.3 Signature-Schemes an

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - nicht unterstützten Signaturalgorithmen dürfen für TLS 1.3 nicht unterstützt werden
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    Und bietet der ClientHello keine nicht unterstützten TLS 1.3 Signature-Schemes an

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_25340-01
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - Zertifikatsprüfung
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit <zertifikat>
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    Und ist der TLS-Handshake <handshake_erwartung>

    @tls_client_fachdienst_hook
    Beispiele: Erfolgsfall - ZETA Client
      | zertifikat                                       | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_good_certificate | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: Erfolgsfall - ZETA Native Client
      | zertifikat                                       | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_good_certificate | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_01
    @tls_client_fachdienst_hook
    Beispiele: Hostname-Prüfung: Vergleich CN oder SAN mit Hostname - ZETA Client
      | zertifikat                                                   | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_different_cn_certificate     | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_san_certificate    | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_01
    @tls_native_client_fachdienst_hook
    Beispiele: Hostname-Prüfung: Vergleich CN oder SAN mit Hostname - ZETA Native Client
      | zertifikat                                                   | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_different_cn_certificate     | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_san_certificate    | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_02
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht vor" - ZETA Client
      | zertifikat                                                | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_02
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht vor" - ZETA Native Client
      | zertifikat                                                | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_03
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht nach" - ZETA Client
      | zertifikat                                          | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_expired_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_03
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht nach" - ZETA Native Client
      | zertifikat                                          | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_expired_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_04
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit basiert auf Zertifikatsvertrauenspfad - ZETA Client
      | zertifikat                                               | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_different_ca_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_04
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit basiert auf Zertifikatsvertrauenspfad - ZETA Native Client
      | zertifikat                                               | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_different_ca_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_25340-01
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - Zertifikatsprüfung
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit <zertifikat>
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    Und ist der TLS-Handshake <handshake_erwartung>

    @tls_client_fachdienst_hook
    Beispiele: Erfolgsfall - ZETA Client
      | zertifikat                                       | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_good_certificate | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: Erfolgsfall - ZETA Native Client
      | zertifikat                                       | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_good_certificate | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_01
    @tls_client_fachdienst_hook
    Beispiele: Hostname-Prüfung: Vergleich CN oder SAN mit Hostname - ZETA Client
      | zertifikat                                                   | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_different_cn_certificate     | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_san_certificate    | erfolgreich         | ZETA Client | ${paths.client.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_01
    @tls_native_client_fachdienst_hook
    Beispiele: Hostname-Prüfung: Vergleich CN oder SAN mit Hostname - ZETA Native Client
      | zertifikat                                                   | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_different_cn_certificate     | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_san_certificate    | erfolgreich         | ZETA Native Client | ${paths.nativeClient.helloZeta} |
      | zeta_tls_test_tool_server_ecdsa_different_cn_san_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_02
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht vor" - ZETA Client
      | zertifikat                                                | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_02
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht vor" - ZETA Native Client
      | zertifikat                                                | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_03
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht nach" - ZETA Client
      | zertifikat                                          | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_expired_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_03
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit Zertifikat "nicht nach" - ZETA Native Client
      | zertifikat                                          | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_expired_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

    @TA_A_25340-01_04
    @tls_client_fachdienst_hook
    Beispiele: Gültigkeit basiert auf Zertifikatsvertrauenspfad - ZETA Client
      | zertifikat                                               | handshake_erwartung | client_name | hello_path                |
      | zeta_tls_test_tool_server_ecdsa_different_ca_certificate | nicht erfolgreich   | ZETA Client | ${paths.client.helloZeta} |

    @TA_A_25340-01_04
    @tls_native_client_fachdienst_hook
    Beispiele: Gültigkeit basiert auf Zertifikatsvertrauenspfad - ZETA Native Client
      | zertifikat                                               | handshake_erwartung | client_name        | hello_path                      |
      | zeta_tls_test_tool_server_ecdsa_different_ca_certificate | nicht erfolgreich   | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @GS-A_5542
  @TA_GS-A_5542_03
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - Alert
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit zeta_tls_test_tool_server_ecdsa_not_yet_valid_certificate
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    # 2a in hexadezimal ist der Alert Code für TLS bad_certificate.
    Und der ZETA Client sendet eine Alert Nachricht mit Description Id "2a"

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_27379-01
  @TA_A_27379-01_12
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - <client_name> - fragt ohne OCSP Stapling den OCSP Responder des Zertifikats direkt ab
    Gegeben sei die TLS 1.2 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit zeta_tls_test_tool_server_ecdsa_ocsp_responder_certificate
    Und TGR setze lokale Variable "ocspResponderPath" auf "/ocsp/tls"
    Und TGR setze lokale Variable "ocspResponderPathPattern" auf "^${ocspResponderPath}.*"
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    Und TGR finde die erste Anfrage mit Pfad "${ocspResponderPathPattern}" und Knoten "${headers.host}" der mit "tiger-proxy(:80)?" übereinstimmt
    Und ist der TLS-Handshake erfolgreich

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |

  @A_27379-01
  @TA_A_27379-01_12
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.3-Verbindungen - <client_name> - fragt ohne OCSP Stapling den OCSP Responder des Zertifikats direkt ab
    Gegeben sei die TLS 1.3 TlsTestTool-Server-Konfigurationsdaten für die unterstützten Cipher-Suiten mit zeta_tls_test_tool_server_ecdsa_ocsp_responder_certificate
    Und TGR setze lokale Variable "ocspResponderPath" auf "/ocsp/tls"
    Und TGR setze lokale Variable "ocspResponderPathPattern" auf "^${ocspResponderPath}.*"
    Wenn TGR sende eine leere GET Anfrage an "<hello_path>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wurde die TLS-Certificate übertragen
    Und TGR finde die erste Anfrage mit Pfad "${ocspResponderPathPattern}" und Knoten "${headers.host}" der mit "tiger-proxy(:80)?" übereinstimmt
    Und ist der TLS-Handshake erfolgreich

    @tls_client_fachdienst_hook
    Beispiele: ZETA Client
      | client_name | hello_path                |
      | ZETA Client | ${paths.client.helloZeta} |

    @tls_native_client_fachdienst_hook
    Beispiele: ZETA Native Client
      | client_name        | hello_path                      |
      | ZETA Native Client | ${paths.nativeClient.helloZeta} |
