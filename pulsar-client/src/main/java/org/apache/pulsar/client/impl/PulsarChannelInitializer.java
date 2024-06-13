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

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.flush.FlushConsolidationHandler;
import io.netty.handler.proxy.Socks5ProxyHandler;
import io.netty.handler.ssl.SslHandler;
import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;
import org.apache.pulsar.client.util.ScheduledExecutorProvider;
import org.apache.pulsar.common.protocol.ByteBufPair;
import org.apache.pulsar.common.protocol.Commands;
import org.apache.pulsar.common.util.PulsarSslConfiguration;
import org.apache.pulsar.common.util.PulsarSslFactory;
import org.apache.pulsar.common.util.SecurityUtility;
import org.apache.pulsar.common.util.keystoretls.NettySSLContextAutoRefreshBuilder;
import org.apache.pulsar.common.util.netty.NettyFutureUtil;

@Slf4j
public class PulsarChannelInitializer extends ChannelInitializer<SocketChannel> {

    public static final String TLS_HANDLER = "tls";

    private final Supplier<ClientCnx> clientCnxSupplier;
    @Getter
    private final boolean tlsEnabled;
    private final boolean tlsHostnameVerificationEnabled;
    private final boolean tlsEnabledWithKeyStore;
    private final InetSocketAddress socks5ProxyAddress;
    private final String socks5ProxyUsername;
    private final String socks5ProxyPassword;

//    private final Supplier<SslContext> sslContextSupplier;
    private final PulsarSslFactory pulsarSslFactory;
    private NettySSLContextAutoRefreshBuilder nettySSLContextAutoRefreshBuilder;

    private static final long TLS_CERTIFICATE_CACHE_MILLIS = TimeUnit.MINUTES.toMillis(1);

    public PulsarChannelInitializer(ClientConfigurationData conf, Supplier<ClientCnx> clientCnxSupplier,
                                    ScheduledExecutorProvider scheduledExecutorProvider)
            throws Exception {
        super();
        this.clientCnxSupplier = clientCnxSupplier;
        this.tlsEnabled = conf.isUseTls();
        this.tlsHostnameVerificationEnabled = conf.isTlsHostnameVerificationEnable();
        this.socks5ProxyAddress = conf.getSocks5ProxyAddress();
        this.socks5ProxyUsername = conf.getSocks5ProxyUsername();
        this.socks5ProxyPassword = conf.getSocks5ProxyPassword();

        this.tlsEnabledWithKeyStore = conf.isUseKeyStoreTls();

        if (tlsEnabled) {
            PulsarSslConfiguration sslConfiguration = buildSslConfiguration(conf);
            this.pulsarSslFactory = (PulsarSslFactory) Class.forName(conf.getSslFactoryPlugin())
                    .getConstructor().newInstance();
            this.pulsarSslFactory.initialize(sslConfiguration);
            this.pulsarSslFactory.createInternalSslContext();
            if (scheduledExecutorProvider != null) {
                ((ScheduledExecutorService) scheduledExecutorProvider.getExecutor())
                        .scheduleWithFixedDelay(this::refreshSslContext, conf.getAutoCertRefreshSeconds(),
                                conf.getAutoCertRefreshSeconds(), TimeUnit.SECONDS);
            }
//            this.pulsarSslFactoryTemp = (PulsarSslFactoryTemp) Class.forName(conf.getSslFactoryPlugin())
//                    .getDeclaredConstructor(Long.TYPE, Long.TYPE)
//                    .newInstance(conf.getAutoCertRefreshSeconds(), 1000L);
//            if (this.pulsarSslFactoryTemp instanceof DefaultPulsarSslFactoryTemp) {
//                ((DefaultPulsarSslFactoryTemp) this.pulsarSslFactoryTemp).configure(
//                        conf.getSslProvider(),
//                        conf.getTlsKeyStoreType(),
//                        conf.getTlsKeyStorePath(),
//                        conf.getTlsKeyStorePassword(),
//                        conf.getTlsTrustStoreType(),
//                        conf.getTlsTrustStorePath(),
//                        conf.getTlsTrustStorePassword(),
//                        conf.getTlsCiphers(),
//                        conf.getTlsProtocols(),
//                        conf.getTlsTrustCertsFilePath(),
//                        conf.getTlsCertificateFilePath(),
//                        conf.getTlsKeyFilePath(),
//                        conf.isTlsAllowInsecureConnection(),
//                        false,
//                        conf.getAuthentication().getAuthData(),
//                        conf.isUseKeyStoreTls());
//            } else {
//                this.pulsarSslFactoryTemp.configure(conf.getSslProvider(),
//                        conf.getTlsCiphers(),
//                        conf.getTlsProtocols(),
//                        conf.isTlsAllowInsecureConnection(),
//                        false,
//                        conf.getAuthentication().getAuthData(),
//                        conf.getSslFactoryPluginParams());
//            }
//            if (tlsEnabledWithKeyStore) {
//                AuthenticationDataProvider authData1 = conf.getAuthentication().getAuthData();
//                if (StringUtils.isBlank(conf.getTlsTrustStorePath())) {
//                    throw new PulsarClientException("Failed to create TLS context, the tlsTrustStorePath"
//                            + " need to be configured if useKeyStoreTls enabled");
//                }
//                nettySSLContextAutoRefreshBuilder = new NettySSLContextAutoRefreshBuilder(
//                            conf.getSslProvider(),
//                            conf.isTlsAllowInsecureConnection(),
//                            conf.getTlsTrustStoreType(),
//                            conf.getTlsTrustStorePath(),
//                            conf.getTlsTrustStorePassword(),
//                            conf.getTlsKeyStoreType(),
//                            conf.getTlsKeyStorePath(),
//                            conf.getTlsKeyStorePassword(),
//                            conf.getTlsCiphers(),
//                            conf.getTlsProtocols(),
//                            TLS_CERTIFICATE_CACHE_MILLIS,
//                            authData1);
//            }
//
//            sslContextSupplier = new ObjectCache<SslContext>(() -> {
//                try {
//                    SslProvider sslProvider = null;
//                    if (conf.getSslProvider() != null) {
//                        sslProvider = SslProvider.valueOf(conf.getSslProvider());
//                    }
//
//                    // Set client certificate if available
//                    AuthenticationDataProvider authData = conf.getAuthentication().getAuthData();
//                    if (authData.hasDataForTls()) {
//                        return authData.getTlsTrustStoreStream() == null
//                                ? SecurityUtility.createNettySslContextForClient(
//                                sslProvider,
//                                conf.isTlsAllowInsecureConnection(),
//                                conf.getTlsTrustCertsFilePath(),
//                                authData.getTlsCertificates(),
//                                authData.getTlsPrivateKey(),
//                                conf.getTlsCiphers(),
//                                conf.getTlsProtocols())
//                                : SecurityUtility.createNettySslContextForClient(sslProvider,
//                                conf.isTlsAllowInsecureConnection(),
//                                authData.getTlsTrustStoreStream(),
//                                authData.getTlsCertificates(), authData.getTlsPrivateKey(),
//                                conf.getTlsCiphers(),
//                                conf.getTlsProtocols());
//                    } else {
//                        return SecurityUtility.createNettySslContextForClient(
//                                sslProvider,
//                                conf.isTlsAllowInsecureConnection(),
//                                conf.getTlsTrustCertsFilePath(),
//                                conf.getTlsCertificateFilePath(),
//                                conf.getTlsKeyFilePath(),
//                                conf.getTlsCiphers(),
//                                conf.getTlsProtocols());
//                    }
//                } catch (Exception e) {
//                    throw new RuntimeException("Failed to create TLS context", e);
//                }
//            }, TLS_CERTIFICATE_CACHE_MILLIS, TimeUnit.MILLISECONDS);
        } else {
//            sslContextSupplier = null;
            pulsarSslFactory = null;
        }
    }

    @Override
    public void initChannel(SocketChannel ch) throws Exception {
        ch.pipeline().addLast("consolidation", new FlushConsolidationHandler(1024, true));

        // Setup channel except for the SsHandler for TLS enabled connections
        ch.pipeline().addLast("ByteBufPairEncoder", tlsEnabled ? ByteBufPair.COPYING_ENCODER : ByteBufPair.ENCODER);

        ch.pipeline().addLast("frameDecoder", new LengthFieldBasedFrameDecoder(
                Commands.DEFAULT_MAX_MESSAGE_SIZE + Commands.MESSAGE_SIZE_FRAME_PADDING, 0, 4, 0, 4));
        ch.pipeline().addLast("handler", clientCnxSupplier.get());
    }

   /**
     * Initialize TLS for a channel. Should be invoked before the channel is connected to the remote address.
     *
     * @param ch      the channel
     * @param sniHost the value of this argument will be passed as peer host and port when creating the SSLEngine (which
     *                in turn will use these values to set SNI header when doing the TLS handshake). Cannot be
     *                <code>null</code>.
     * @return a {@link CompletableFuture} that completes when the TLS is set up.
     */
    CompletableFuture<Channel> initTls(Channel ch, InetSocketAddress sniHost) {
        Objects.requireNonNull(ch, "A channel is required");
        Objects.requireNonNull(sniHost, "A sniHost is required");
        if (!tlsEnabled) {
            throw new IllegalStateException("TLS is not enabled in client configuration");
        }
        CompletableFuture<Channel> initTlsFuture = new CompletableFuture<>();
        ch.eventLoop().execute(() -> {
            try {
//                SslHandler handler = tlsEnabledWithKeyStore
//                        ? new SslHandler(nettySSLContextAutoRefreshBuilder.get()
//                                .createSSLEngine(sniHost.getHostString(), sniHost.getPort()))
//                        : sslContextSupplier.get().newHandler(ch.alloc(), sniHost.getHostString(), sniHost.getPort());
                SslHandler handler = new SslHandler(pulsarSslFactory
                        .createClientSslEngine(sniHost.getHostName(), sniHost.getPort()));

                if (tlsHostnameVerificationEnabled) {
                    SecurityUtility.configureSSLHandler(handler);
                }

                ch.pipeline().addFirst(TLS_HANDLER, handler);
                initTlsFuture.complete(ch);
            } catch (Throwable t) {
                initTlsFuture.completeExceptionally(t);
            }
        });

        return initTlsFuture;
    }

    CompletableFuture<Channel> initSocks5IfConfig(Channel ch) {
        CompletableFuture<Channel> initSocks5Future = new CompletableFuture<>();
        if (socks5ProxyAddress != null) {
            ch.eventLoop().execute(() -> {
                try {
                    Socks5ProxyHandler socks5ProxyHandler =
                            new Socks5ProxyHandler(socks5ProxyAddress, socks5ProxyUsername, socks5ProxyPassword);
                    ch.pipeline().addFirst(socks5ProxyHandler.protocol(), socks5ProxyHandler);
                    initSocks5Future.complete(ch);
                } catch (Throwable t) {
                    initSocks5Future.completeExceptionally(t);
                }
            });
        } else {
            initSocks5Future.complete(ch);
        }

        return initSocks5Future;
    }

    CompletableFuture<Channel> initializeClientCnx(Channel ch,
                                                   InetSocketAddress logicalAddress,
                                                   InetSocketAddress unresolvedPhysicalAddress) {
        return NettyFutureUtil.toCompletableFuture(ch.eventLoop().submit(() -> {
            final ClientCnx cnx = (ClientCnx) ch.pipeline().get("handler");

            if (cnx == null) {
                throw new IllegalStateException("Missing ClientCnx. This should not happen.");
            }

            if (!logicalAddress.equals(unresolvedPhysicalAddress)) {
                // We are connecting through a proxy. We need to set the target broker in the ClientCnx object so that
                // it can be specified when sending the CommandConnect.
                cnx.setTargetBroker(logicalAddress);
            }

            cnx.setRemoteHostName(unresolvedPhysicalAddress.getHostString());

            return ch;
        }));
    }

    protected PulsarSslConfiguration buildSslConfiguration(ClientConfigurationData config)
            throws PulsarClientException {
        return PulsarSslConfiguration.builder()
                .tlsProvider(config.getSslProvider())
                .tlsKeyStoreType(config.getTlsKeyStoreType())
                .tlsKeyStorePath(config.getTlsKeyStorePath())
                .tlsKeyStorePassword(config.getTlsKeyStorePassword())
                .tlsTrustStoreType(config.getTlsTrustStoreType())
                .tlsTrustStorePath(config.getTlsTrustStorePath())
                .tlsTrustStorePassword(config.getTlsTrustStorePassword())
                .tlsCiphers(config.getTlsCiphers())
                .tlsProtocols(config.getTlsProtocols())
                .tlsTrustCertsFilePath(config.getTlsTrustCertsFilePath())
                .tlsCertificateFilePath(config.getTlsCertificateFilePath())
                .tlsKeyFilePath(config.getTlsKeyFilePath())
                .allowInsecureConnection(config.isTlsAllowInsecureConnection())
                .requireTrustedClientCertOnConnect(false)
                .tlsEnabledWithKeystore(config.isUseKeyStoreTls())
                .tlsCustomParams(config.getSslFactoryPluginParams())
                .authData(config.getAuthentication().getAuthData())
                .serverMode(false)
                .build();
    }

    protected void refreshSslContext() {
        try {
            this.pulsarSslFactory.update();
        } catch (Exception e) {
            log.error("Failed to refresh SSL context", e);
        }
    }
}

