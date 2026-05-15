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

@UseCase_TLS_01
@no_proxy
Funktionalität: TLS-Konformität ZETA Guard

  @A_26669-01
  @TA_A_26669-01_01
  Szenario: PDP Authorization Server - eingehende TLS-1.2-Verbindungen terminieren
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "${keycloak_url}"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich

  @A_18464
  @GS-A_5542
  @TA_A_18464_01
  @TA_GS-A_5542_01
  @MASVS-CRYPTO
  @MASVS-NETWORK
  Szenariogrundriss: TLS 1.1 darf nicht unterstützt werden.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" wurden nur für TLS 1.1 erstellt
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 46 in hexadezimal entspricht 70 in dezimal und ist der Alert Code für TLS Protocol Version Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "46"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @GS-A_5526
  @TA_GS-A_5526_01
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.2-Renegotiation-Indication-Extension - ZETA Guard - TLS-Renegotiation-Indication-Extension.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Und ist die Erweiterung renegotiation_info im ServerHello vorhanden
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @GS-A_5526
  @TA_GS-A_5526_01
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.2-Renegotiation wird RFC-5746-konform verarbeitet - ZETA Guard.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" für TLS Renegotiation
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Und wird die TLS-Handshake-renegotiation gestartet
    Und ist die TLS-Handshake-renegotiation RFC-5746-konform erfolgreich oder wird mit no_renegotiation oder handshake_failure abgelehnt
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @GS-A_5526
  @TA_GS-A_5526_01
  @MASVS-NETWORK
  Szenariogrundriss: Fehlerhafte TLS 1.2 renegotiation_info extension im initialen ClientHello wird abgelehnt - ZETA Guard.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit einer fehlerhaften renegotiation_info extension
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake nicht erfolgreich
    Und wird der ServerHello-Record nicht empfangen
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_21275-01
  @TA_A_21275-01_03
  @MASVS-CRYPTO
  Szenariogrundriss: TLS 1.2 Verbindungen, zulässige Hashfunktionen bei Signaturen im TLS-Handshake - ZETA Guard - mindestens SHA-256 unterstützen
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden nicht unterstützten Hashfunktionen wurden festgelegt:
      | MD5    |
      | SHA1   |
      | SHA224 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 28 in hexadezimal entspricht 40 in dezimal und ist der Alert Code für TLS Handshake Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "28"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_21275-01
  @TA_A_21275-01_01
  @TA_A_21275-01_04
  @MASVS-CRYPTO
  Szenariogrundriss: TLS 1.2 Verbindungen, zulässige Hashfunktionen bei Signaturen im TLS-Handshake - ZETA Guard - erlaubte Hashfunktionen
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden unterstützten Hashfunktionen wurden festgelegt:
      | SHA256 |
      | SHA384 |
      | SHA512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und verwendet der Server-Schlüsselaustausch eine der unterstützten Hashfunktionen
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_21275-01
  @TA_A_21275-01_01
  @TA_A_21275-01_04
  @MASVS-CRYPTO
  Szenariogrundriss: TLS 1.3 Verbindungen, zulässige Hashfunktionen bei Signaturen im TLS-Handshake - ZETA Guard - erlaubte Hashfunktionen
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden TLS 1.3 Signature-Schemes wurden festgelegt:
      | ecdsa_secp256r1_sha256            |
      | ecdsa_secp384r1_sha384            |
      | ecdsa_brainpoolP256r1tls13_sha256 |
      | ecdsa_brainpoolP384r1tls13_sha384 |
      | ecdsa_brainpoolP512r1tls13_sha512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und verwendet der Certificate-Verify eine der unterstützten Hashfunktionen
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_28868
  @TA_A_28868_05
  @MASVS-CRYPTO
  Szenariogrundriss: Die Zeta-Guard-Instanz verwendet ausschließlich Schlüssellängen und Domainparameter, insbesondere ECC-Kurvenparameter, die den Empfehlungen der TR-02102-2 entsprechen.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden unterstützten Hashfunktionen wurden festgelegt:
      | SHA256 |
      | SHA384 |
      | SHA512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und verwendet der Server ein Zertifikat mit Schlüssellängen und Domainparameter nach [TR-02102-2]
    Und verwendet der Server-Schlüsselaustausch eine der unterstützten Kurven
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |


  @A_28868
  @TA_A_28868_05
  @MASVS-CRYPTO
  Szenariogrundriss: Die Zeta-Guard-Instanz verwendet ausschließlich Schlüssellängen und Domainparameter, insbesondere ECC-Kurvenparameter, die den Empfehlungen der TR-02102-2 entsprechen für TLS 1.3.
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden TLS 1.3 Signature-Schemes wurden festgelegt:
      | ecdsa_secp256r1_sha256            |
      | ecdsa_secp384r1_sha384            |
      | ecdsa_brainpoolP256r1tls13_sha256 |
      | ecdsa_brainpoolP384r1tls13_sha384 |
      | ecdsa_brainpoolP512r1tls13_sha512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und verwendet der Server ein Zertifikat mit Schlüssellängen und Domainparameter nach [TR-02102-2]
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_28868
  @TA_A_28868_03
  @MASVS-CRYPTO
  Szenariogrundriss: Cipher-Suiten außerhalb der nach TR-02102-2 für TLS 1.2 zulässigen Menge werden nicht ausgehandelt.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" für die nicht unterstützten Cipher-Suiten
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wird der ServerHello-Record nicht empfangen
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_28868
  @TA_A_28868_03
  @MASVS-CRYPTO
  Szenariogrundriss: Optionale Cipher-Suiten aus TR-02102-2 für TLS 1.2 zulässigen Menge werden nicht ausgehandelt.
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" für die optional unterstützten Cipher-Suiten
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wird der ServerHello-Record nicht empfangen
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_28868
  @TA_A_28868_02
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.2-Verbindungen - ZETA Guard - PEP HTTP Proxy - elliptische Kurven.
    # Profile:
    # p256: secp256r1 (0017)
    # p384: secp384r1 (0018)
    # unsupported_mix: alle nach Tls12Policy verbotenen Gruppen.
    # Beispiele: brainpoolP256r1tls13, secp192r1, secp224r1, secp521r1 (P-521), secp256k1, x25519, x448, ffdhe*
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" für das unterstützte-Gruppen-Profil "<supported_group>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wird der Server-Key-Exchange-Datensatz <ske_erwartung>
    Und ist der TLS-Handshake <handshake_erwartung>
    Beispiele:
      | host             | supported_group | handshake_erwartung | ske_erwartung  |
      # ZETA Guard Ingress
      | ${zeta_base_url} | p256            | erfolgreich         | gesendet       |
      | ${zeta_base_url} | p384            | erfolgreich         | gesendet       |
      | ${zeta_base_url} | unsupported_mix | nicht erfolgreich   | nicht gesendet |
      # ZETA Keycloak
      | ${keycloak_url}  | p256            | erfolgreich         | gesendet       |
      | ${keycloak_url}  | p384            | erfolgreich         | gesendet       |
      | ${keycloak_url}  | unsupported_mix | nicht erfolgreich   | nicht gesendet |

  @A_28868
  @TA_A_28868_02
  @TA_A_28868_05
  @MASVS-CRYPTO
  Szenariogrundriss: TLS-1.3-Verbindungen - ZETA Guard - PEP HTTP Proxy - elliptische Kurven.
    # Profile:
    # p256: secp256r1 (0017)
    # p384: secp384r1 (0018)
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" für das unterstützte-Gruppen-Profil "<supported_group>"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist das unterstützte-Gruppen-Profil "<supported_group>" in der Server-Key-Share verwendet
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             | supported_group |
      # ZETA Guard Ingress
      | ${zeta_base_url} | p256            |
      | ${zeta_base_url} | p384            |
      # ZETA Keycloak
      | ${keycloak_url}  | p256            |
      | ${keycloak_url}  | p384            |

  @A_28868
  @GS-A_5542
  @TA_A_28868_02
  @TA_GS-A_5542_01
  @MASVS-CRYPTO
  @MASVS-NETWORK
  Szenariogrundriss: TLS-1.3-Verbindungen - ZETA Guard - PEP HTTP Proxy - unsupported elliptische Kurven.
    # Profile:
    # unsupported_mix: secp521r1, x25519, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" für das unterstützte-Gruppen-Profil "unsupported_mix"
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 28 in hexadezimal entspricht 40 in dezimal und ist der Alert Code für TLS Handshake Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "28"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @A_28868
  @TA_A_28868_01
  @MASVS-CRYPTO
  Szenariogrundriss: Bei TLS 1.2 MÜSSEN TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 und TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 unterstützt werden.
    # Profile:
    # ecdhe_ecdsa_aes_128_gcm_sha256 -> TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC0,0x2B)
    # ecdhe_ecdsa_aes_256_gcm_sha384 -> TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC0,0x2C)
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" für das Cipher-Suite-Profil <ciphersuite_profil>
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             | ciphersuite_profil           |
      # ZETA Guard Ingress
      | ${zeta_base_url} | ecdhe_ecdsa_aes_128_gcm_sha256 |
      | ${zeta_base_url} | ecdhe_ecdsa_aes_256_gcm_sha384 |
      # ZETA Keycloak
      | ${keycloak_url}  | ecdhe_ecdsa_aes_128_gcm_sha256 |
      | ${keycloak_url}  | ecdhe_ecdsa_aes_256_gcm_sha384 |

  @A_28868
  @TA_A_28868_04
  @MASVS-CRYPTO
  Szenariogrundriss: Bei TLS 1.3 MÜSSEN TLS_AES_128_GCM_SHA256 und TLS_AES_256_GCM_SHA384 unterstützt werden.
    # Profile:
    # aes_128_gcm_sha256 -> TLS_AES_128_GCM_SHA256 (0x13,0x01)
    # aes_256_gcm_sha384 -> TLS_AES_256_GCM_SHA384 (0x13,0x02)
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" für das Cipher-Suite-Profil <ciphersuite_profil>
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und wird TLS 1.3 unterstützt oder das Szenario wird übersprungen
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             | ciphersuite_profil |
      # ZETA Guard Ingress
      | ${zeta_base_url} | aes_128_gcm_sha256 |
      | ${zeta_base_url} | aes_256_gcm_sha384 |
      # ZETA Keycloak
      | ${keycloak_url}  | aes_128_gcm_sha256 |
      | ${keycloak_url}  | aes_256_gcm_sha384 |

  Szenariogrundriss: RSA-Signaturalgorithmen dürfen für TLS 1.2 nicht unterstützt werden
    Gegeben sei die TLS 1.2 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden TLS 1.2 Signatur-Hash-Algorithmen wurden festgelegt:
      | RSA_MD5    |
      | RSA_SHA1   |
      | RSA_SHA224 |
      | RSA_SHA256 |
      | RSA_SHA384 |
      | RSA_SHA512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 28 in hexadezimal entspricht 40 in dezimal und ist der Alert Code für TLS Handshake Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "28"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  @GS-A_5542
  @TA_GS-A_5542_01
  @MASVS-NETWORK
  Szenariogrundriss: RSA-Signaturalgorithmen (pkcs1) dürfen für TLS 1.3 nicht unterstützt werden
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden nicht empfehlende TLS 1.3 Signature-Schemes wurden festgelegt:
      | rsa_pkcs1_sha256 |
      | rsa_pkcs1_sha384 |
      | rsa_pkcs1_sha512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 28 in hexadezimal entspricht 40 in dezimal und ist der Alert Code für TLS Handshake Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "28"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  Szenariogrundriss: Erlaubt-Signaturalgorithmen dürfen für TLS 1.3 unterstützt werden
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden TLS 1.3 Signature-Schemes wurden festgelegt:
      | ecdsa_secp256r1_sha256            |
      | ecdsa_secp384r1_sha384            |
      | ecdsa_brainpoolP256r1tls13_sha256 |
      | ecdsa_brainpoolP384r1tls13_sha384 |
      | ecdsa_brainpoolP512r1tls13_sha512 |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    Und ist der TLS-Handshake erfolgreich
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |

  Szenariogrundriss: Unerlaubt-Signaturalgorithmen (kein RSA) dürfen für TLS 1.3 nicht unterstützt werden
    Gegeben sei die TLS 1.3 TlsTestTool-Konfigurationsdaten für den Host "<host>" mit den folgenden TLS 1.3 Signature-Schemes wurden festgelegt:
      | rsa_pss_rsae_sha256               |
      | rsa_pss_rsae_sha384               |
      | rsa_pss_rsae_sha512               |
      | rsa_pss_pss_sha256                |
      | rsa_pss_pss_sha384                |
      | rsa_pss_pss_sha512                |
    Dann die Tls-Test-Tool-Protokolle abrufen
    Und die TCP-IP-Verbindung wird hergestellt
    # 28 in hexadezimal entspricht 40 in dezimal und ist der Alert Code für TLS Handshake Failure.
    Und akzeptiert der ZETA Guard Endpunkt das ClientHello nicht und sendet eine Alert Nachricht mit Description Id "28"
    Beispiele:
      | host             |
      # ZETA Guard Ingress
      | ${zeta_base_url} |
      # ZETA Keycloak
      | ${keycloak_url}  |
