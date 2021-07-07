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

import org.apache.flink.runtime.rest.handler.util.HandlerUtils;
import org.apache.flink.runtime.rest.messages.ErrorResponseBody;

import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelInboundHandlerAdapter;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaders;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.server.KerberosAuthenticationHandler;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Netty handler for kerberos authentication on the Server side. This class was inspired by {@link
 * KerberosAuthenticationHandler}.
 */
@ChannelHandler.Sharable
public class ServerKerberosHttpAuthenticator extends ChannelInboundHandlerAdapter {

    private static final Logger LOG =
            LoggerFactory.getLogger(ServerKerberosHttpAuthenticator.class);

    private final Subject serverSubject;
    private final GSSManager gssManager;
    private final Map<String, String> responseHeaders;

    public ServerKerberosHttpAuthenticator(
            Subject serverSubject, GSSManager gssManager, Map<String, String> responseHeaders) {
        this.serverSubject = serverSubject;
        this.gssManager = gssManager;
        this.responseHeaders = new HashMap<>(requireNonNull(responseHeaders));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof HttpRequest) {
            try {
                HttpHeaders headers = ((HttpRequest) msg).headers();

                String authorization = headers.get(KerberosAuthenticator.AUTHORIZATION);
                if (authorization == null
                        || !authorization.startsWith(KerberosAuthenticator.NEGOTIATE)) {
                    String errorMessage = "Missing authorization header";
                    LOG.debug(errorMessage);
                    responseHeaders.put(
                            KerberosAuthenticator.WWW_AUTHENTICATE,
                            KerberosAuthenticator.NEGOTIATE);
                    HandlerUtils.sendResponse(
                            ctx,
                            true,
                            errorMessage,
                            HttpResponseStatus.UNAUTHORIZED,
                            responseHeaders);
                    return;
                }

                boolean authenticated =
                        Subject.doAs(
                                serverSubject,
                                (PrivilegedExceptionAction<Boolean>)
                                        () -> checkCredentials(ctx, authorization));
                if (authenticated) {
                    ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
                } else {
                    final String errorMessage = "Invalid credentials";
                    LOG.error(errorMessage);
                    HandlerUtils.sendErrorResponse(
                            ctx,
                            false,
                            new ErrorResponseBody(errorMessage),
                            HttpResponseStatus.UNAUTHORIZED,
                            responseHeaders);
                }
            } catch (Exception e) {
                LOG.error("Exception while authenticating user", e);
                HandlerUtils.sendErrorResponse(
                        ctx,
                        false,
                        new ErrorResponseBody("Invalid credentials"),
                        HttpResponseStatus.UNAUTHORIZED,
                        responseHeaders);
            }
        } else {
            // Only HttpRequests are authenticated
            ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
        }
    }

    private boolean checkCredentials(ChannelHandlerContext ctx, String authorization)
            throws GSSException, IOException {
        LOG.debug("SPNEGO authentication started");

        Base64 base64 = new Base64(0);
        byte[] clientToken =
                base64.decode(
                        authorization.substring(KerberosAuthenticator.NEGOTIATE.length()).trim());
        LOG.debug("Client token is {} bytes long", clientToken.length);

        String serverPrincipal = KerberosUtil.getTokenServerName(clientToken);
        if (!serverPrincipal.startsWith("HTTP/")) {
            String errorMessage =
                    "Invalid server principal " + serverPrincipal + "decoded from client request";
            LOG.error(errorMessage);
            HandlerUtils.sendErrorResponse(
                    ctx,
                    false,
                    new ErrorResponseBody(errorMessage),
                    HttpResponseStatus.UNAUTHORIZED,
                    responseHeaders);
            return false;
        } else {
            LOG.debug("Valid server principal found");
        }

        GSSContext gssContext = null;
        GSSCredential gssCreds = null;
        try {
            LOG.debug("SPNEGO initiated with server principal {}", serverPrincipal);
            gssCreds =
                    gssManager.createCredential(
                            gssManager.createName(
                                    serverPrincipal, KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID),
                            GSSCredential.INDEFINITE_LIFETIME,
                            new Oid[] {
                                KerberosUtil.GSS_SPNEGO_MECH_OID, KerberosUtil.GSS_KRB5_MECH_OID
                            },
                            GSSCredential.ACCEPT_ONLY);
            gssContext = gssManager.createContext(gssCreds);
            byte[] serverToken = gssContext.acceptSecContext(clientToken, 0, clientToken.length);
            if (ArrayUtils.isNotEmpty(serverToken)) {
                LOG.debug("Putting server token to response headers");
                responseHeaders.put(
                        KerberosAuthenticator.WWW_AUTHENTICATE,
                        KerberosAuthenticator.NEGOTIATE + " " + base64.encodeToString(serverToken));
            } else {
                LOG.debug("Server token is empty so not putting anything to response headers");
            }
            if (!gssContext.isEstablished()) {
                String errorMessage = "Could not establish gss context";
                LOG.error(errorMessage);
                HandlerUtils.sendErrorResponse(
                        ctx,
                        false,
                        new ErrorResponseBody(errorMessage),
                        HttpResponseStatus.UNAUTHORIZED,
                        responseHeaders);
                return false;
            } else {
                String clientPrincipal = gssContext.getSrcName().toString();
                KerberosName kerberosName = new KerberosName(clientPrincipal);
                String userName = kerberosName.getShortName();
                LOG.debug(
                        "SPNEGO completed for user {} client principal [{}]",
                        userName,
                        clientPrincipal);
                return true;
            }
        } finally {
            if (gssContext != null) {
                gssContext.dispose();
            }
            if (gssCreds != null) {
                gssCreds.dispose();
            }
        }
    }
}
