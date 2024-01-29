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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.client.api.AuthenticationDataProvider;

// Need a new config for how long to wait for the first new ssl context
@Slf4j
public abstract class SslFactory {

    protected final long timeToWaitForFirstSslContext;
    protected final long refreshTime;
    protected long lastRefreshTime;
    protected SSLContext internalSslContext;
    protected final ReadWriteLock readWriteLock;
    protected final Lock readLock;
    protected final Lock writeLock;

    public SslFactory(long certRefreshInSec, long timeToWaitForFirstSslContext) {
        this.refreshTime = TimeUnit.SECONDS.toMillis(certRefreshInSec);
        this.lastRefreshTime = -1;
        this.timeToWaitForFirstSslContext = timeToWaitForFirstSslContext;
        this.readWriteLock = new ReentrantReadWriteLock();
        this.readLock = readWriteLock.readLock();
        this.writeLock = readWriteLock.writeLock();
        if (log.isDebugEnabled()) {
            log.debug("Certs will be refreshed every {} seconds", certRefreshInSec);
        }
    }

    public abstract SSLEngine getClientSslEngine(String peerHost, int peerPort);

    public abstract SSLEngine getServerSslEngine() throws GeneralSecurityException, IOException;

    public abstract boolean needsUpdate();

    public abstract void update() throws Exception;

    public abstract void configure(String sslProviderString,
                                   Set<String> ciphers,
                                   Set<String> protocols,
                                   boolean allowInsecureConnection,
                                   boolean requireTrustedClientCertOnConnect,
                                   AuthenticationDataProvider authData,
                                   String tlsCustomParams);


    public SSLContext getInternalSslContext() {
        long now = System.currentTimeMillis();
        if (this.internalSslContext == null || (refreshTime <= 0
                || now > (lastRefreshTime + refreshTime) && needsUpdate())) {
            if (this.writeLock.tryLock()) {
               try {
                   update();
                   lastRefreshTime = System.currentTimeMillis();
               } catch (Exception e) {
                   log.error("Exception while trying to refresh ssl context {}", e.getMessage(), e);
               } finally {
                   this.writeLock.unlock();
               }
            } else if (this.internalSslContext == null) {
                try {
                    if (this.readLock.tryLock(timeToWaitForFirstSslContext, TimeUnit.MILLISECONDS)) {
                        this.readLock.unlock();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        return this.internalSslContext;
    }
}
