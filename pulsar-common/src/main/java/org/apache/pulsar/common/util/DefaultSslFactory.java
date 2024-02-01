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
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.common.util.keystoretls.KeyStoreSSLContext;

public class DefaultSslFactory extends SslFactory {

    protected Set<String> tlsCiphers;
    protected Set<String> tlsProtocols;
    protected boolean tlsAllowInsecureConnection;
    protected boolean tlsRequireTrustedClientCertOnConnect;
    protected String tlsProvider;
    protected String tlsTrustStoreType;
    protected String tlsTrustStorePassword;
    protected String tlsKeyStoreType;
    protected String tlsKeyStorePassword;
    protected FileModifiedTimeUpdater tlsKeyStore;
    protected FileModifiedTimeUpdater tlsTrustStore;
    protected FileModifiedTimeUpdater tlsTrustCertsFilePath;
    protected FileModifiedTimeUpdater tlsCertificateFilePath;
    protected FileModifiedTimeUpdater tlsKeyFilePath;

    protected AuthenticationDataProvider authData;
    protected boolean isKeyStoreEnabled;
    protected InputStream tlsTrustCertsStream;

    protected boolean isTlsTrustStoreStreamProvided;
    protected final String[] defaultSslEnabledProtocols = {"TLSv1.3", "TLSv1.2"};

    public DefaultSslFactory(long certRefreshInSec, long timeToWaitForFirstSslContext) {
        super(certRefreshInSec, timeToWaitForFirstSslContext);
    }

    @Override
    public SSLEngine getClientSslEngine(String peerHost, int peerPort) {
        return createSSLEngine(peerHost, peerPort, NetworkMode.CLIENT);
    }

    @Override
    public SSLEngine getServerSslEngine() {
        return createSSLEngine("", 0, NetworkMode.SERVER);
    }

    @Override
    public boolean needsUpdate() {
        if (isKeyStoreEnabled) {
            return  (tlsKeyStore != null && tlsKeyStore.checkAndRefresh())
                    || (tlsTrustStore != null && tlsTrustStore.checkAndRefresh());
        } else {
            return tlsTrustCertsFilePath.checkAndRefresh() || tlsCertificateFilePath.checkAndRefresh()
                    || tlsKeyFilePath.checkAndRefresh();
        }
    }

    public void configure(String sslProviderString, String keyStoreTypeString, String keyStore, String keyStorePassword,
                          String trustStoreTypeString, String trustStore, String trustStorePassword,
                          Set<String> ciphers, Set<String> protocols, String trustCertsFilePath,
                          String certificateFilePath, String keyFilePath, boolean allowInsecureConnection,
                          boolean requireTrustedClientCertOnConnect, AuthenticationDataProvider authData,
                          boolean isKeyStoreEnabled) {
        this.isKeyStoreEnabled = isKeyStoreEnabled;
        this.tlsProvider = sslProviderString;
        this.authData = authData;
        if (this.isKeyStoreEnabled) {
            this.tlsKeyStoreType = keyStoreTypeString;
            this.tlsKeyStore = new FileModifiedTimeUpdater(keyStore);
            this.tlsKeyStorePassword = keyStorePassword;
            this.tlsTrustStoreType = trustStoreTypeString;
            this.tlsTrustStore = new FileModifiedTimeUpdater(trustStore);
            this.tlsTrustStorePassword = trustStorePassword;
        } else {
            if (authData != null && authData.hasDataForTls()) {
                this.tlsCertificateFilePath = new FileModifiedTimeUpdater(authData.getTlsCertificateFilePath());
                this.tlsKeyFilePath = new FileModifiedTimeUpdater(authData.getTlsPrivateKeyFilePath());
                if (authData.getTlsTrustStoreStream() != null) {
                    this.isTlsTrustStoreStreamProvided = true;
                    this.tlsTrustCertsStream = authData.getTlsTrustStoreStream();
                } else {
                    this.tlsTrustCertsFilePath = new FileModifiedTimeUpdater(trustCertsFilePath);
                }
            } else {
                this.tlsCertificateFilePath = new FileModifiedTimeUpdater(certificateFilePath);
                this.tlsTrustCertsFilePath = new FileModifiedTimeUpdater(trustCertsFilePath);
                this.tlsKeyFilePath = new FileModifiedTimeUpdater(keyFilePath);
            }
        }
        this.tlsCiphers = ciphers;
        this.tlsProtocols = protocols;
        this.tlsAllowInsecureConnection = allowInsecureConnection;
        this.tlsRequireTrustedClientCertOnConnect = requireTrustedClientCertOnConnect;
    }

    @Override
    public synchronized void update() throws GeneralSecurityException, IOException {
        if (this.isKeyStoreEnabled) {
            this.internalSslContext = buildKeystoreSslContext();
        } else {
            this.internalSslContext = buildSslContext();
        }
    }

    @Override
    public void configure(String sslProviderString,
                          Set<String> ciphers,
                          Set<String> protocols,
                          boolean allowInsecureConnection,
                          boolean requireTrustedClientCertOnConnect,
                          AuthenticationDataProvider authData,
                          String tlsCustomParams) {
        //noop
    }


    // TODO call respective sslcontext based on mode of server or client.
    private SSLContext buildKeystoreSslContext() throws GeneralSecurityException, IOException {
        KeyStoreSSLContext keyStoreSSLContext = KeyStoreSSLContext.createServerKeyStoreSslContext(this.tlsProvider,
                this.tlsKeyStoreType, this.tlsKeyStore.getFileName(), this.tlsKeyStorePassword,
                this.tlsAllowInsecureConnection, this.tlsTrustStoreType, this.tlsTrustStore.getFileName(),
                this.tlsTrustStorePassword, this.tlsRequireTrustedClientCertOnConnect, this.tlsCiphers,
                this.tlsProtocols);
        return keyStoreSSLContext.getSslContext();
    }
    private SSLContext buildSslContext() throws GeneralSecurityException {
        return isTlsTrustStoreStreamProvided
                ? SecurityUtility.createSslContext(this.tlsAllowInsecureConnection,
                        SecurityUtility.loadCertificatesFromPemStream(this.tlsTrustCertsStream),
                        SecurityUtility.loadCertificatesFromPemFile(this.tlsCertificateFilePath.getFileName()),
                        SecurityUtility.loadPrivateKeyFromPemFile(this.tlsKeyFilePath.getFileName()),
                        this.tlsProvider) :
                SecurityUtility.createSslContext(this.tlsAllowInsecureConnection,
                        this.tlsTrustCertsFilePath.getFileName(),
                        this.tlsCertificateFilePath.getFileName(),
                        this.tlsKeyFilePath.getFileName(),
                        this.tlsProvider);
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
            if (this.tlsRequireTrustedClientCertOnConnect) {
                sslParams.setNeedClientAuth(true);
            } else {
                sslParams.setWantClientAuth(true);
            }
        }
        if (this.tlsProtocols != null && this.tlsProtocols.size() > 0) {
            sslParams.setProtocols(this.tlsProtocols.toArray(new String[0]));
        } else {
            sslParams.setProtocols(defaultSslEnabledProtocols);
        }
        if (this.tlsCiphers != null && !this.tlsCiphers.isEmpty()) {
            sslParams.setCipherSuites(this.tlsCiphers.toArray(new String[0]));
        }
        sslEngine.setSSLParameters(sslParams);
        return sslEngine;
    }

    private void validateSslContext(SSLContext sslContext) {
        if (sslContext == null) {
            throw new IllegalStateException("SSLContext creation failed.");
        }
    }


}
