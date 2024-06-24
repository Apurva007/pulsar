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
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.api.KeyStoreParams;
import org.apache.pulsar.common.util.keystoretls.KeyStoreSSLContext;

public class DefaultPulsarSslFactory implements PulsarSslFactory {

    private PulsarSslConfiguration config;
    private final AtomicReference<SSLContext> internalSslContext = new AtomicReference<>();

    protected FileModifiedTimeUpdater tlsKeyStore;
    protected FileModifiedTimeUpdater tlsTrustStore;
    protected FileModifiedTimeUpdater tlsTrustCertsFilePath;
    protected FileModifiedTimeUpdater tlsCertificateFilePath;
    protected FileModifiedTimeUpdater tlsKeyFilePath;
    protected AuthenticationDataProvider authData;
    protected boolean isTlsTrustStoreStreamProvided;
    protected final String[] defaultSslEnabledProtocols = {"TLSv1.3", "TLSv1.2"};
    protected String tlsKeystoreType;
    protected String tlsKeystorePath;
    protected String tlsKeystorePassword;

    @Override
    public void initialize(PulsarSslConfiguration config) {
        this.config = config;
        AuthenticationDataProvider authData = this.config.getAuthData();
        if (this.config.isTlsEnabledWithKeystore()) {
            if (authData != null && authData.hasDataForTls()) {
                KeyStoreParams authParams = authData.getTlsKeyStoreParams();
                if (authParams != null) {
                    this.tlsKeystoreType = authParams.getKeyStoreType();
                    this.tlsKeystorePath = authParams.getKeyStorePath();
                    this.tlsKeystorePassword = authParams.getKeyStorePassword();
                }
            }
            if (this.tlsKeystoreType == null) {
                this.tlsKeystoreType = this.config.getTlsKeyStoreType();
            }
            if (this.tlsKeystorePath == null) {
                this.tlsKeystorePath = this.config.getTlsKeyStorePath();
            }
            if (this.tlsKeystorePassword == null) {
                this.tlsKeystorePassword = this.config.getTlsKeyStorePassword();
            }
            this.tlsKeyStore = new FileModifiedTimeUpdater(this.tlsKeystorePath);
            this.tlsTrustStore = new FileModifiedTimeUpdater(this.config.getTlsTrustStorePath());
        } else {
            if (authData != null && authData.hasDataForTls()) {
                if (authData.getTlsTrustStoreStream() != null) {
                    this.isTlsTrustStoreStreamProvided = true;
//                    this.tlsTrustCertsStream = authData.getTlsTrustStoreStream();
//                    this.tlsCertificates = authData.getTlsCertificates();
//                    this.tlsPrivateKey = authData.getTlsPrivateKey();
                } else {
                    this.tlsTrustCertsFilePath = new FileModifiedTimeUpdater(this.config.getTlsTrustCertsFilePath());
                }
                this.authData = authData;
            } else {
                this.tlsCertificateFilePath = new FileModifiedTimeUpdater(this.config.getTlsCertificateFilePath());
                this.tlsTrustCertsFilePath = new FileModifiedTimeUpdater(this.config.getTlsTrustCertsFilePath());
                this.tlsKeyFilePath = new FileModifiedTimeUpdater(this.config.getTlsKeyFilePath());
            }
        }
    }

    @Override
    public SSLEngine createClientSslEngine(String peerHost, int peerPort) {
        return createSSLEngine(peerHost, peerPort, NetworkMode.CLIENT);
    }

    @Override
    public SSLEngine createServerSslEngine() {
        return createSSLEngine("", 0, NetworkMode.SERVER);
    }

    @Override
    public boolean needsUpdate() {
        if (this.config.isTlsEnabledWithKeystore()) {
            return  (this.tlsKeyStore != null && this.tlsKeyStore.checkAndRefresh())
                    || (this.tlsTrustStore != null && this.tlsTrustStore.checkAndRefresh());
        } else {
            if (this.authData != null && this.authData.hasDataForTls()) {
              return true;
            } else {
                return this.tlsTrustCertsFilePath.checkAndRefresh() || this.tlsCertificateFilePath.checkAndRefresh()
                        || this.tlsKeyFilePath.checkAndRefresh();
            }
        }
    }

    @Override
    public void createInternalSslContext() throws Exception {
        if (this.config.isTlsEnabledWithKeystore()) {
            this.internalSslContext.set(buildKeystoreSslContext(this.config.isServerMode()));
        } else {
            this.internalSslContext.set(buildSslContext());
        }
    }

    @Override
    public SSLContext getInternalSslContext() {
        if (this.internalSslContext.get() == null) {
            throw new RuntimeException("Internal SSL context is not initialized. "
                    + "Please call createInternalSslContext() first.");
        }
        return this.internalSslContext.get();
    }

    private SSLContext buildKeystoreSslContext(boolean isServerMode) throws GeneralSecurityException, IOException {
        KeyStoreSSLContext keyStoreSSLContext;
        if (isServerMode) {
             keyStoreSSLContext = KeyStoreSSLContext.createServerKeyStoreSslContext(this.config.getTlsProvider(),
                     this.tlsKeystoreType, this.tlsKeyStore.getFileName(),
                     this.tlsKeystorePassword, this.config.isAllowInsecureConnection(),
                     this.config.getTlsTrustStoreType(), this.tlsTrustStore.getFileName(),
                     this.config.getTlsTrustStorePassword(), this.config.isRequireTrustedClientCertOnConnect(),
                     this.config.getTlsCiphers(), this.config.getTlsProtocols());
        } else {
            keyStoreSSLContext = KeyStoreSSLContext.createClientKeyStoreSslContext(this.config.getTlsProvider(),
                    this.tlsKeystoreType, this.tlsKeyStore.getFileName(),
                    this.tlsKeystorePassword, this.config.isAllowInsecureConnection(),
                    this.config.getTlsTrustStoreType(), this.tlsTrustStore.getFileName(),
                    this.config.getTlsTrustStorePassword(), this.config.getTlsCiphers(),
                    this.config.getTlsProtocols());
        }
        return keyStoreSSLContext.createSSLContext();
    }

    private SSLContext buildSslContext() throws GeneralSecurityException {
//        return isTlsTrustStoreStreamProvided
//                ? SecurityUtility.createSslContext(this.config.isAllowInsecureConnection(),
//                SecurityUtility.loadCertificatesFromPemStream(this.authData.getTlsTrustStoreStream()),
//                this.authData.getTlsCertificates(),
//                this.authData.getTlsPrivateKey(),
//                this.config.getTlsProvider()) :
//                SecurityUtility.createSslContext(this.config.isAllowInsecureConnection(),
//                        this.tlsTrustCertsFilePath.getFileName(),
//                        this.tlsCertificateFilePath.getFileName(),
//                        this.tlsKeyFilePath.getFileName(),
//                        this.config.getTlsProvider());
        if (this.authData != null && this.authData.hasDataForTls()) {
            if (this.isTlsTrustStoreStreamProvided) {
                return SecurityUtility.createSslContext(this.config.isAllowInsecureConnection(),
                        SecurityUtility.loadCertificatesFromPemStream(this.authData.getTlsTrustStoreStream()),
                        this.authData.getTlsCertificates(),
                        this.authData.getTlsPrivateKey(),
                        this.config.getTlsProvider());
            } else {
                return SecurityUtility.createSslContext(this.config.isAllowInsecureConnection(),
                        SecurityUtility.loadCertificatesFromPemFile(this.tlsTrustCertsFilePath.getFileName()),
                        this.authData.getTlsCertificates(),
                        this.authData.getTlsPrivateKey(),
                        this.config.getTlsProvider());
            }
        } else {
            return SecurityUtility.createSslContext(this.config.isAllowInsecureConnection(),
                    this.tlsTrustCertsFilePath.getFileName(),
                    this.tlsCertificateFilePath.getFileName(),
                    this.tlsKeyFilePath.getFileName(),
                    this.config.getTlsProvider());
        }
    }

    private SSLEngine createSSLEngine(String peerHost, int peerPort, NetworkMode mode) {
        SSLEngine sslEngine;
        SSLParameters sslParams;
        SSLContext sslContext = getInternalSslContext();
        validateSslContext(sslContext);
        if (mode == NetworkMode.CLIENT) {
            sslEngine = sslContext.createSSLEngine(peerHost, peerPort);
            sslEngine.setUseClientMode(true);
            sslParams = sslEngine.getSSLParameters();
        } else {
            sslEngine = sslContext.createSSLEngine();
            sslEngine.setUseClientMode(false);
            sslParams = sslEngine.getSSLParameters();
            if (this.config.isRequireTrustedClientCertOnConnect()) {
                sslParams.setNeedClientAuth(true);
            } else {
                sslParams.setWantClientAuth(true);
            }
        }
        if (this.config.getTlsProtocols() != null && !this.config.getTlsProtocols().isEmpty()) {
            sslParams.setProtocols(this.config.getTlsProtocols().toArray(new String[0]));
        } else {
            sslParams.setProtocols(defaultSslEnabledProtocols);
        }
        if (this.config.getTlsCiphers() != null && !this.config.getTlsCiphers().isEmpty()) {
            sslParams.setCipherSuites(this.config.getTlsCiphers().toArray(new String[0]));
        }
        sslEngine.setSSLParameters(sslParams);
        return sslEngine;
    }

    private void validateSslContext(SSLContext sslContext) {
        if (sslContext == null) {
            throw new IllegalStateException("SSLContext creation failed.");
        }
    }

    @Override
    public void close() throws Exception {
        // noop
    }
}
