/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.broker.service.persistent;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertEqualsNoOrder;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import java.lang.reflect.Field;
import java.util.Set;
import java.util.TreeSet;
import org.apache.bookkeeper.mledger.Position;
import org.apache.bookkeeper.mledger.PositionFactory;
import org.apache.bookkeeper.util.collections.ConcurrentLongLongHashMap;
import org.apache.pulsar.common.util.collections.ConcurrentLongLongPairHashMap;
import org.apache.pulsar.utils.ConcurrentBitmapSortedLongPairSet;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test(groups = "broker")
public class MessageRedeliveryControllerTest {
    @DataProvider(name = "allowOutOfOrderDelivery")
    public Object[][] dataProvider() {
        return new Object[][] { { true }, { false } };
    }

    @Test(dataProvider = "allowOutOfOrderDelivery", timeOut = 10000)
    public void testAddAndRemove(boolean allowOutOfOrderDelivery) throws Exception {
        MessageRedeliveryController controller = new MessageRedeliveryController(allowOutOfOrderDelivery);

        Field messagesToRedeliverField = MessageRedeliveryController.class.getDeclaredField("messagesToRedeliver");
        messagesToRedeliverField.setAccessible(true);
        ConcurrentBitmapSortedLongPairSet messagesToRedeliver =
                (ConcurrentBitmapSortedLongPairSet) messagesToRedeliverField.get(controller);

        Field hashesToBeBlockedField = MessageRedeliveryController.class.getDeclaredField("hashesToBeBlocked");
        hashesToBeBlockedField.setAccessible(true);
        ConcurrentLongLongPairHashMap hashesToBeBlocked = (ConcurrentLongLongPairHashMap) hashesToBeBlockedField
                .get(controller);

        Field hashesRefCountField = MessageRedeliveryController.class.getDeclaredField("hashesRefCount");
        hashesRefCountField.setAccessible(true);
        ConcurrentLongLongHashMap hashesRefCount = (ConcurrentLongLongHashMap) hashesRefCountField.get(controller);

        if (allowOutOfOrderDelivery) {
            assertNull(hashesToBeBlocked);
            assertNull(hashesRefCount);
        } else {
            assertNotNull(hashesToBeBlocked);
            assertNotNull(hashesRefCount);
        }

        assertTrue(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 0);
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 0);
            assertEquals(hashesRefCount.size(), 0);
        }

        controller.add(1, 1);
        controller.add(1, 2);

        assertFalse(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 2);
        assertTrue(messagesToRedeliver.contains(1, 1));
        assertTrue(messagesToRedeliver.contains(1, 2));
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 0);
            assertFalse(hashesToBeBlocked.containsKey(1, 1));
            assertFalse(hashesToBeBlocked.containsKey(1, 2));
            assertEquals(hashesRefCount.size(), 0);
        }

        controller.remove(1, 1);
        controller.remove(1, 2);

        assertTrue(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 0);
        assertFalse(messagesToRedeliver.contains(1, 1));
        assertFalse(messagesToRedeliver.contains(1, 2));
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 0);
            assertEquals(hashesRefCount.size(), 0);
        }

        controller.add(2, 1, 100);
        controller.add(2, 2, 101);
        controller.add(2, 3, 101);

        assertFalse(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 3);
        assertTrue(messagesToRedeliver.contains(2, 1));
        assertTrue(messagesToRedeliver.contains(2, 2));
        assertTrue(messagesToRedeliver.contains(2, 3));
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 3);
            assertEquals(hashesToBeBlocked.get(2, 1).first, 100);
            assertEquals(hashesToBeBlocked.get(2, 2).first, 101);
            assertEquals(hashesToBeBlocked.get(2, 3).first, 101);
            assertEquals(hashesRefCount.size(), 2);
            assertEquals(hashesRefCount.get(100), 1);
            assertEquals(hashesRefCount.get(101), 2);
        }

        controller.remove(2, 1);
        controller.remove(2, 2);

        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 1);
            assertEquals(hashesToBeBlocked.get(2, 3).first, 101);
            assertEquals(hashesRefCount.size(), 1);
            assertEquals(hashesRefCount.get(100), -1);
            assertEquals(hashesRefCount.get(101), 1);
        }

        controller.clear();
        assertTrue(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 0);
        assertTrue(messagesToRedeliver.isEmpty());
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 0);
            assertTrue(hashesToBeBlocked.isEmpty());
            assertEquals(hashesRefCount.size(), 0);
            assertTrue(hashesRefCount.isEmpty());
        }

        controller.add(2, 2, 201);
        controller.add(1, 3, 100);
        controller.add(3, 1, 300);
        controller.add(2, 1, 200);
        controller.add(3, 2, 301);
        controller.add(1, 2, 101);
        controller.add(1, 1, 100);

        controller.removeAllUpTo(1, 3);
        assertEquals(messagesToRedeliver.size(), 4);
        assertTrue(messagesToRedeliver.contains(2, 1));
        assertTrue(messagesToRedeliver.contains(2, 2));
        assertTrue(messagesToRedeliver.contains(3, 1));
        assertTrue(messagesToRedeliver.contains(3, 2));
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 4);
            assertEquals(hashesToBeBlocked.get(2, 1).first, 200);
            assertEquals(hashesToBeBlocked.get(2, 2).first, 201);
            assertEquals(hashesToBeBlocked.get(3, 1).first, 300);
            assertEquals(hashesToBeBlocked.get(3, 2).first, 301);
            assertEquals(hashesRefCount.size(), 4);
            assertEquals(hashesRefCount.get(200), 1);
            assertEquals(hashesRefCount.get(201), 1);
            assertEquals(hashesRefCount.get(300), 1);
            assertEquals(hashesRefCount.get(301), 1);
        }

        controller.removeAllUpTo(3, 1);
        assertEquals(messagesToRedeliver.size(), 1);
        assertTrue(messagesToRedeliver.contains(3, 2));
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 1);
            assertEquals(hashesToBeBlocked.get(3, 2).first, 301);
            assertEquals(hashesRefCount.size(), 1);
            assertEquals(hashesRefCount.get(301), 1);
        }

        controller.removeAllUpTo(5, 10);
        assertTrue(controller.isEmpty());
        assertEquals(messagesToRedeliver.size(), 0);
        if (!allowOutOfOrderDelivery) {
            assertEquals(hashesToBeBlocked.size(), 0);
            assertEquals(hashesRefCount.size(), 0);
        }
    }

    @Test(dataProvider = "allowOutOfOrderDelivery", timeOut = 10000)
    public void testContainsStickyKeyHashes(boolean allowOutOfOrderDelivery) throws Exception {
        MessageRedeliveryController controller = new MessageRedeliveryController(allowOutOfOrderDelivery);
        controller.add(1, 1, 100);
        controller.add(1, 2, 101);
        controller.add(1, 3, 102);
        controller.add(2, 2, 103);
        controller.add(2, 1, 104);

        if (allowOutOfOrderDelivery) {
            assertFalse(controller.containsStickyKeyHashes(Set.of(100)));
            assertFalse(controller.containsStickyKeyHashes(Set.of(101, 102, 103)));
            assertFalse(controller.containsStickyKeyHashes(Set.of(104, 105)));
        } else {
            assertTrue(controller.containsStickyKeyHashes(Set.of(100)));
            assertTrue(controller.containsStickyKeyHashes(Set.of(101, 102, 103)));
            assertTrue(controller.containsStickyKeyHashes(Set.of(104, 105)));
        }

        assertFalse(controller.containsStickyKeyHashes(Set.of()));
        assertFalse(controller.containsStickyKeyHashes(Set.of(99)));
        assertFalse(controller.containsStickyKeyHashes(Set.of(105, 106)));
    }

    @Test(dataProvider = "allowOutOfOrderDelivery", timeOut = 10000)
    public void testGetMessagesToReplayNow(boolean allowOutOfOrderDelivery) throws Exception {
        MessageRedeliveryController controller = new MessageRedeliveryController(allowOutOfOrderDelivery);
        controller.add(2, 2);
        controller.add(1, 3);
        controller.add(3, 1);
        controller.add(2, 1);
        controller.add(3, 2);
        controller.add(1, 2);
        controller.add(1, 1);

        if (allowOutOfOrderDelivery) {
            // The entries are sorted by ledger ID but not by entry ID
            Position[] actual1 = controller.getMessagesToReplayNow(3, item -> true).toArray(new Position[3]);
            Position[] expected1 = { PositionFactory.create(1, 1),
                    PositionFactory.create(1, 2), PositionFactory.create(1, 3) };
            assertEqualsNoOrder(actual1, expected1);
        } else {
            // The entries are completely sorted
            Set<Position> actual2 = controller.getMessagesToReplayNow(6, item -> true);
            Set<Position> expected2 = new TreeSet<>();
            expected2.add(PositionFactory.create(1, 1));
            expected2.add(PositionFactory.create(1, 2));
            expected2.add(PositionFactory.create(1, 3));
            expected2.add(PositionFactory.create(2, 1));
            expected2.add(PositionFactory.create(2, 2));
            expected2.add(PositionFactory.create(3, 1));
            assertEquals(actual2, expected2);
        }
    }
}
