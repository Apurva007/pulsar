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
package org.apache.pulsar.client.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.client.api.SubscriptionType;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * End to end transaction test.
 */
@Slf4j
@Test(groups = "broker-impl")
public class TransactionEndToEndWithoutBatchIndexAckTest extends TransactionEndToEndTest {

    @BeforeClass(alwaysRun = true)
    protected void setup() throws Exception {
        conf.setAcknowledgmentAtBatchIndexLevelEnabled(false);
        setUpBase(1, NUM_PARTITIONS, TOPIC_OUTPUT, TOPIC_PARTITION);
        admin.topics().createPartitionedTopic(TOPIC_MESSAGE_ACK_TEST, 1);
    }

    // TODO need to fix which using transaction with individual ack for failover subscription
    @Test
    public void txnIndividualAckTestBatchAndFailoverSub() throws Exception {
        conf.setAcknowledgmentAtBatchIndexLevelEnabled(true);
        txnAckTest(true, 200, SubscriptionType.Failover);
    }

    @Override
    @Test(dataProvider = "unackMessagesCountParams", enabled = false)
    public void testUnackMessageAfterAckAllMessages(boolean batchSend, boolean batchAck, boolean asyncAck)
            throws Exception {
        super.testUnackMessageAfterAckAllMessages(batchSend, batchAck, asyncAck);
    }

    @Override
    @Test(dataProvider = "enableBatch", enabled = false)
    public void testAckWithTransactionReduceUnAckMessageCount(boolean enableBatch) throws Exception {
        super.testAckWithTransactionReduceUnAckMessageCount(enableBatch);
    }
}
