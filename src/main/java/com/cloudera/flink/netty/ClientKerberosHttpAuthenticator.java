/*
 * Licensed to Cloudera, Inc. under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.flink.netty;

import org.apache.flink.runtime.security.SecurityConfiguration;
import org.apache.flink.runtime.security.modules.JaasModule;
import org.apache.flink.util.Preconditions;
import org.apache.flink.util.StringUtils;

import org.apache.flink.shaded.netty4.io.netty.channel.ChannelDuplexHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelPromise;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;

import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/** Netty handler for kerberos authentication on the Client side. */
@ChannelHandler.Sharable
public final class ClientKerberosHttpAuthenticator extends ChannelDuplexHandler {

    private static final Logger LOG =
            LoggerFactory.getLogger(ClientKerberosHttpAuthenticator.class);

    private static class KerberosConfiguration extends javax.security.auth.login.Configuration {
        private final SecurityConfiguration securityConfig;

        public KerberosConfiguration(SecurityConfiguration securityConfig) {
            this.securityConfig = securityConfig;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            LOG.debug("getAppConfigurationEntry(" + name + ")");
            return JaasModule.getAppConfigurationEntries(securityConfig);
        }
    }

    private final SecurityConfiguration securityConfig;

    public ClientKerberosHttpAuthenticator(SecurityConfiguration securityConfig) {
        this.securityConfig = securityConfig;
    }

    private Optional<String> obtainToken(String host) throws Exception {
        LOG.debug("Obtaining token for host {}", host);

        LoginContext loginContext = null;
        try {
            Subject subject = null;
            if (!StringUtils.isNullOrWhitespaceOnly(securityConfig.getPrincipal())) {
                Set<Principal> principals = new HashSet<>();
                principals.add(new KerberosPrincipal(securityConfig.getPrincipal()));
                subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());
            }
            loginContext =
                    new LoginContext("", subject, null, new KerberosConfiguration(securityConfig));
            LOG.debug("Logging in");
            loginContext.login();
            LOG.debug("Login successful");
            subject = loginContext.getSubject();
            return Optional.of(
                    Subject.doAs(
                            subject,
                            (PrivilegedExceptionAction<String>)
                                    () -> {
                                        GSSManager gssManager = GSSManager.getInstance();
                                        GSSContext gssContext = null;
                                        try {
                                            GSSName serviceName =
                                                    gssManager.createName(
                                                            "HTTP/" + host,
                                                            KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID);
                                            gssContext =
                                                    gssManager.createContext(
                                                            serviceName,
                                                            KerberosUtil.GSS_KRB5_MECH_OID,
                                                            null,
                                                            GSSContext.DEFAULT_LIFETIME);
                                            gssContext.requestCredDeleg(true);
                                            gssContext.requestMutualAuth(true);

                                            byte[] inToken = new byte[0];
                                            LOG.debug(
                                                    "Obtaining token for service {}", serviceName);
                                            byte[] outToken =
                                                    gssContext.initSecContext(
                                                            inToken, 0, inToken.length);
                                            LOG.debug("Token obtained successfully");
                                            Base64 base64 = new Base64(0);
                                            return base64.encodeToString(outToken);
                                        } finally {
                                            if (gssContext != null) {
                                                gssContext.dispose();
                                            }
                                        }
                                    }));
        } finally {
            if (loginContext != null) {
                loginContext.logout();
            }
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
            throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest httpRequest = (HttpRequest) msg;
            try {
                LOG.debug("Adding authorization header to HTTP request");

                String host = httpRequest.headers().get(HttpHeaderNames.HOST);
                Preconditions.checkNotNull(host, "Host name not found in HTTP headers");
                int lastColonIndex = host.lastIndexOf(":");
                if (lastColonIndex >= 0) {
                    host = host.substring(0, lastColonIndex);
                }

                Optional<String> token = obtainToken(host);
                token.ifPresent(
                        s ->
                                httpRequest
                                        .headers()
                                        .set(
                                                HttpHeaderNames.AUTHORIZATION,
                                                KerberosAuthenticator.NEGOTIATE + " " + s));
            } catch (Exception e) {
                LOG.error("Exception while adding authorization header to HTTP request", e);
            }
        }
        super.write(ctx, msg, promise);
    }
}
