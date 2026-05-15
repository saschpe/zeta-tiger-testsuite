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

package de.gematik.zeta.services.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One load-driver instance configuration.
 *
 * @param fachdienstUrl          fachdienst URL used by the instance
 * @param disableTlsVerification whether TLS verification should be disabled
 * @param smbKeystoreB64         base64 encoded SMC-B keystore
 * @param smbKeystoreAlias       keystore alias
 * @param smbKeystorePassword    keystore password
 */
public record LoadDriverInstanceConfig(
    String fachdienstUrl,
    boolean disableTlsVerification,
    @JsonProperty("smbKeystoreB64") String smbKeystoreB64,
    @JsonProperty("smbKeystoreAlias") String smbKeystoreAlias,
    @JsonProperty("smbKeystorePassword") String smbKeystorePassword) {

}
