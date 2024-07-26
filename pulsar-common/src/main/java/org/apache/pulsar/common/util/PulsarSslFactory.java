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
package org.apache.pulsar.common.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

/**
 * Factory for generating SSL Context and SSL Engine using {@link PulsarSslConfiguration}.
 */
public interface PulsarSslFactory extends AutoCloseable {

    /**
     * Initializes the PulsarSslFactory.
     * @param config {@link PulsarSslConfiguration} object required for initialization
     */
    void initialize(PulsarSslConfiguration config);

    /**
     * Creates a Client {@link SSLEngine} utilizing the peer hostname, peer port and {@link PulsarSslConfiguration}
     * object provided during initialization.
     *
     * @param peerHost the name of the peer host
     * @param peerPort the port number of the peer
     * @return {@link SSLEngine}
     */
    SSLEngine createClientSslEngine(ByteBufAllocator buf, String peerHost, int peerPort);

    /**
     * Creates a Server {@link SSLEngine} utilizing the {@link PulsarSslConfiguration} object provided during
     * initialization.
     *
     * @return {@link SSLEngine}
     */
    SSLEngine createServerSslEngine(ByteBufAllocator buf);

    /**
     * Returns a boolean value indicating {@link SSLContext} should be refreshed.
     *
     * @return {@code true} if {@link SSLContext} should be refreshed.
     */
    boolean needsUpdate();

    /**
     * Update the internal {@link SSLContext}.
     * @throws Exception if there are any issues generating the new {@link SSLContext}
     */
    default void update() throws Exception {
        if (this.needsUpdate()) {
            this.createInternalSslContext();
        }
    }

    /**
     * Creates {@link SSLContext} if keystore based tls is being setup. If non-keystore setup, then it should create
     * {@link  SSLContext} for https connections and {@link SslContext} for netty connections.
     * @throws Exception if there are any issues creating the new {@link SSLContext}
     */
    void createInternalSslContext() throws Exception;

    /**
     * Get the internally stored {@link SSLContext}.
     *
     * @return {@link SSLContext}
     * @throws RuntimeException if the {@link SSLContext} object has not yet been initialized.
     */
    SSLContext getInternalSslContext();

    /**
     * Get the internally stored {@link SslContext}.
     *
     * @return {@link SslContext}
     * @throws RuntimeException if the {@link SslContext} object has not yet been initialized.
     */
    SslContext getInternalNettySslContext();

}