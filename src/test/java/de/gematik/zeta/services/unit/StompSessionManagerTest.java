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

package de.gematik.zeta.services.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.gematik.zeta.services.StompSessionManager;
import de.gematik.zeta.services.WebSocketClientFactory;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.messaging.simp.stomp.StompHeaders;
import org.springframework.messaging.simp.stomp.StompSession;
import org.springframework.test.util.ReflectionTestUtils;

/** Unit tests for {@link StompSessionManager}. */
class StompSessionManagerTest {

  /**
   * Verifies that subscriptions are tracked after the STOMP client accepts the subscription.
   */
  @Test
  void subscribeTracksSubscriptionWithoutRequiringReceipt() {
    var session = mock(StompSession.class);
    var subscription = mock(StompSession.Subscription.class);
    when(session.isConnected()).thenReturn(true);
    when(session.subscribe(any(StompHeaders.class), any())).thenReturn(subscription);
    var manager = new StompSessionManager(new WebSocketClientFactory());
    ReflectionTestUtils.setField(manager, "session", session);

    manager.subscribe("/user/queue/erezept", "sub-crud");

    @SuppressWarnings("unchecked")
    var activeSubscriptions =
        (java.util.Map<String, String>) ReflectionTestUtils.getField(manager, "activeSubscriptions");
    assertThat(activeSubscriptions).containsEntry("sub-crud", "/user/queue/erezept");

    var headersCaptor = ArgumentCaptor.forClass(StompHeaders.class);
    verify(session).subscribe(headersCaptor.capture(), any());
    assertThat(headersCaptor.getValue().getReceipt()).isNull();
  }
}
