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
package org.apache.pulsar.proxy.server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.flush.FlushConsolidationHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.pulsar.client.util.ExecutorProvider;
import org.apache.pulsar.common.protocol.Commands;
import org.apache.pulsar.common.protocol.OptionalProxyProtocolDecoder;
import org.apache.pulsar.common.util.PulsarSslConfiguration;
import org.apache.pulsar.common.util.PulsarSslFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Initialize service channel handlers.
 *
 */
public class ServiceChannelInitializer extends ChannelInitializer<SocketChannel> {
    private static final Logger log = LoggerFactory.getLogger(ServiceChannelInitializer.class);

    public static final String TLS_HANDLER = "tls";
    private final ProxyService proxyService;
    private final boolean enableTls;
    private final boolean tlsEnabledWithKeyStore;
    private final int brokerProxyReadTimeoutMs;
    private final int maxMessageSize;

//    private SslContextAutoRefreshBuilder<SslContext> serverSslCtxRefresher;
//    private NettySSLContextAutoRefreshBuilder serverSSLContextAutoRefreshBuilder;
    private PulsarSslFactory sslFactory;
    private ScheduledExecutorService scheduledExecutorService;

    public ServiceChannelInitializer(ProxyService proxyService, ProxyConfiguration serviceConfig, boolean enableTls)
            throws Exception {
        super();
        this.proxyService = proxyService;
        this.enableTls = enableTls;
        this.tlsEnabledWithKeyStore = serviceConfig.isTlsEnabledWithKeyStore();
        this.brokerProxyReadTimeoutMs = serviceConfig.getBrokerProxyReadTimeoutMs();
        this.maxMessageSize = serviceConfig.getMaxMessageSize();

        if (enableTls) {
            this.scheduledExecutorService = Executors.newSingleThreadScheduledExecutor(
                    new ExecutorProvider.ExtendedThreadFactory("pulsar-proxy-service-channel-tls-refresh"));
            PulsarSslConfiguration sslConfiguration = buildSslConfiguration(serviceConfig);
            this.sslFactory = (PulsarSslFactory) Class.forName(serviceConfig.getSslFactoryPlugin())
                    .getConstructor().newInstance();
            this.sslFactory.initialize(sslConfiguration);
            this.sslFactory.createInternalSslContext();
            scheduledExecutorService.scheduleWithFixedDelay(this::refreshSslContext,
                    serviceConfig.getTlsCertRefreshCheckDurationSec(),
                    serviceConfig.getTlsCertRefreshCheckDurationSec(), TimeUnit.SECONDS);
//            this.sslFactory = (SslFactory) Class.forName(serviceConfig.getSslFactoryPlugin())
//                    .getDeclaredConstructor(Long.TYPE, Long.TYPE)
//                    .newInstance(serviceConfig.getTlsCertRefreshCheckDurationSec(), 1000L);
//            this.sslFactory = new DefaultSslFactory(serviceConfig.getTlsCertRefreshCheckDurationSec(), 600);
//            if (this.sslFactory instanceof DefaultSslFactory) {
//                ((DefaultSslFactory) this.sslFactory).configure(serviceConfig.getTlsProvider(),
//                        serviceConfig.getTlsKeyStoreType(),
//                        serviceConfig.getTlsKeyStore(),
//                        serviceConfig.getTlsKeyStorePassword(),
//                        serviceConfig.getTlsTrustStoreType(),
//                        serviceConfig.getTlsTrustStore(),
//                        serviceConfig.getTlsTrustStorePassword(),
//                        serviceConfig.getTlsCiphers(),
//                        serviceConfig.getTlsProtocols(),
//                        serviceConfig.getTlsTrustCertsFilePath(),
//                        serviceConfig.getTlsCertificateFilePath(),
//                        serviceConfig.getTlsKeyFilePath(),
//                        serviceConfig.isTlsAllowInsecureConnection(),
//                        serviceConfig.isTlsRequireTrustedClientCertOnConnect(),
//                        null,
//                        serviceConfig.isTlsEnabledWithKeyStore());
//            } else {
//                this.sslFactory.configure(serviceConfig.getTlsProvider(),
//                        serviceConfig.getTlsCiphers(),
//                        serviceConfig.getTlsProtocols(),
//                        serviceConfig.isTlsAllowInsecureConnection(),
//                        serviceConfig.isTlsRequireTrustedClientCertOnConnect(),
//                        null,
//                        serviceConfig.getSslFactoryPluginParams());
//            }
//            if (tlsEnabledWithKeyStore) {
//                serverSSLContextAutoRefreshBuilder = new NettySSLContextAutoRefreshBuilder(
//                        serviceConfig.getTlsProvider(),
//                        serviceConfig.getTlsKeyStoreType(),
//                        serviceConfig.getTlsKeyStore(),
//                        serviceConfig.getTlsKeyStorePassword(),
//                        serviceConfig.isTlsAllowInsecureConnection(),
//                        serviceConfig.getTlsTrustStoreType(),
//                        serviceConfig.getTlsTrustStore(),
//                        serviceConfig.getTlsTrustStorePassword(),
//                        serviceConfig.isTlsRequireTrustedClientCertOnConnect(),
//                        serviceConfig.getTlsCiphers(),
//                        serviceConfig.getTlsProtocols(),
//                        serviceConfig.getTlsCertRefreshCheckDurationSec());
//            } else {
//                SslProvider sslProvider = null;
//                if (serviceConfig.getTlsProvider() != null) {
//                    sslProvider = SslProvider.valueOf(serviceConfig.getTlsProvider());
//                }
//                serverSslCtxRefresher = new NettyServerSslContextBuilder(
//                        sslProvider,
//                        serviceConfig.isTlsAllowInsecureConnection(),
//                        serviceConfig.getTlsTrustCertsFilePath(), serviceConfig.getTlsCertificateFilePath(),
//                        serviceConfig.getTlsKeyFilePath(), serviceConfig.getTlsCiphers(),
//                        serviceConfig.getTlsProtocols(),
//                        serviceConfig.isTlsRequireTrustedClientCertOnConnect(),
//                        serviceConfig.getTlsCertRefreshCheckDurationSec());
//            }
        }
//        } else {
//            this.serverSslCtxRefresher = null;
//            this.sslFactory = null;
//        }
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ch.pipeline().addLast("consolidation", new FlushConsolidationHandler(1024,
                true));
//        if (serverSslCtxRefresher != null && this.enableTls) {
//            SslContext sslContext = serverSslCtxRefresher.get();
//            if (sslContext != null) {
//                ch.pipeline().addLast(TLS_HANDLER, sslContext.newHandler(ch.alloc()));
//            }
//        } else if (this.tlsEnabledWithKeyStore && serverSSLContextAutoRefreshBuilder != null) {
//            ch.pipeline().addLast(TLS_HANDLER,
//                    new SslHandler(serverSSLContextAutoRefreshBuilder.get().createSSLEngine()));
//        }
        if (this.enableTls) {
            ch.pipeline().addLast(TLS_HANDLER, new SslHandler(this.sslFactory.createServerSslEngine()));
        }
        if (brokerProxyReadTimeoutMs > 0) {
            ch.pipeline().addLast("readTimeoutHandler",
                    new ReadTimeoutHandler(brokerProxyReadTimeoutMs, TimeUnit.MILLISECONDS));
        }
        if (proxyService.getConfiguration().isHaProxyProtocolEnabled()) {
            ch.pipeline().addLast(OptionalProxyProtocolDecoder.NAME, new OptionalProxyProtocolDecoder());
        }
        ch.pipeline().addLast("frameDecoder", new LengthFieldBasedFrameDecoder(
                this.maxMessageSize + Commands.MESSAGE_SIZE_FRAME_PADDING, 0, 4, 0, 4));

        ch.pipeline().addLast("handler", new ProxyConnection(proxyService, proxyService.getDnsAddressResolverGroup()));
    }

    protected PulsarSslConfiguration buildSslConfiguration(ProxyConfiguration config) {
        return PulsarSslConfiguration.builder()
                .tlsProvider(config.getBrokerClientSslProvider())
                .tlsKeyStoreType(config.getBrokerClientTlsKeyStoreType())
                .tlsKeyStorePath(config.getBrokerClientTlsKeyStore())
                .tlsKeyStorePassword(config.getBrokerClientTlsKeyStorePassword())
                .tlsTrustStoreType(config.getBrokerClientTlsTrustStoreType())
                .tlsTrustStorePath(config.getBrokerClientTlsTrustStore())
                .tlsTrustStorePassword(config.getBrokerClientTlsTrustStorePassword())
                .tlsCiphers(config.getBrokerClientTlsCiphers())
                .tlsProtocols(config.getBrokerClientTlsProtocols())
                .tlsTrustCertsFilePath(config.getBrokerClientTrustCertsFilePath())
                .tlsCertificateFilePath(config.getBrokerClientCertificateFilePath())
                .tlsKeyFilePath(config.getBrokerClientKeyFilePath())
                .allowInsecureConnection(config.isTlsAllowInsecureConnection())
                .requireTrustedClientCertOnConnect(false)
                .tlsEnabledWithKeystore(config.isBrokerClientTlsEnabledWithKeyStore())
                .tlsCustomParams(config.getBrokerClientSslFactoryPluginParams())
                .authData(null)
                .serverMode(true)
                .build();
    }

    protected void refreshSslContext() {
        try {
            this.sslFactory.update();
        } catch (Exception e) {
            log.error("Failed to refresh SSL context", e);
        }
    }
}
