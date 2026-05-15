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

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Runtime context returned after load-driver preparation.
 *
 * @param client                      HTTP client used for cleanup and background reset
 * @param baseUrl                     normalized load-driver base URL
 * @param cleanupAfterTest            whether instances should be deleted after the JMeter run
 * @param instancePathsFile           generated JMeter instance-path binding file
 * @param backgroundResetIds          instance ids for background reset, or {@code null}
 * @param backgroundResetPathTemplate path template for background reset requests
 * @param backgroundResetStepTimeout  request timeout for background reset requests
 */
public record LoadDriverContext(
    HttpClient client,
    String baseUrl,
    boolean cleanupAfterTest,
    Path instancePathsFile,
    List<Integer> backgroundResetIds,
    String backgroundResetPathTemplate,
    Duration backgroundResetStepTimeout) {

}
