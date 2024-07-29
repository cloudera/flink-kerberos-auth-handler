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

import org.apache.flink.configuration.Configuration;
import org.apache.flink.runtime.io.network.netty.InboundChannelHandlerFactory;
import org.apache.flink.util.ConfigurationException;

import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;

import com.cloudera.flink.config.KerberosAuthOptions;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

public class ServerKerberosAuthHandlerFactory implements InboundChannelHandlerFactory {

    private static final Logger LOG =
            LoggerFactory.getLogger(ServerKerberosAuthHandlerFactory.class);

    public ServerKerberosAuthHandlerFactory() {}

    @Override
    public String toString() {
        return super.toString() + " priority: " + priority();
    }

    @Override
    public int priority() {
        return 1;
    }

    @Override
    public Optional<ChannelHandler> createHandler(
            Configuration configuration, Map<String, String> responseHeaders)
            throws ConfigurationException {
        if (!configuration.getBoolean(KerberosAuthOptions.SPNEGO_AUTH_ENABLED)) {
            return Optional.empty();
        }

        String keytab =
                configuration
                        .getOptional(KerberosAuthOptions.SECURITY_SPNEGO_KEYTAB)
                        .orElseThrow(
                                () ->
                                        new ConfigurationException(
                                                KerberosAuthOptions.SECURITY_SPNEGO_KEYTAB.key()
                                                        + " must be configured if kerberos auth is enabled."));
        String principal =
                configuration
                        .getOptional(KerberosAuthOptions.SECURITY_SPNEGO_PRINCIPAL)
                        .orElseThrow(
                                () ->
                                        new ConfigurationException(
                                                KerberosAuthOptions.SECURITY_SPNEGO_PRINCIPAL.key()
                                                        + " must be configured if kerberos auth is enabled."));

        File keytabFile = new File(keytab);
        if (!keytabFile.exists()) {
            throw new ConfigurationException("Keytab does not exist: " + keytab);
        }

        if (!principal.startsWith("HTTP/")) {
            throw new ConfigurationException("Kerberos auth principal must start with 'HTTP/'");
        }

        String[] resolvedPrincipals = getPrincipals(keytab, principal);

        KeyTab keytabInstance = KeyTab.getInstance(keytabFile);
        Subject serverSubject = new Subject();
        serverSubject.getPrivateCredentials().add(keytabInstance);
        for (String resolvedPrincipal : resolvedPrincipals) {
            Principal krbPrincipal = new KerberosPrincipal(resolvedPrincipal);
            LOG.debug("Using keytab {}, for principal {}", keytab, krbPrincipal);
            serverSubject.getPrincipals().add(krbPrincipal);
        }

        GSSManager gssManager;
        try {
            gssManager =
                    Subject.doAs(
                            serverSubject,
                            (PrivilegedExceptionAction<GSSManager>) GSSManager::getInstance);
        } catch (PrivilegedActionException e) {
            throw new ConfigurationException(e.getException());
        }

        LOG.info(
                "Creating kerberos authentication handler with response headers {}",
                responseHeaders);
        return Optional.of(
                new ServerKerberosHttpAuthenticator(serverSubject, gssManager, responseHeaders));
    }

    private String[] getPrincipals(String keytab, String principal) throws ConfigurationException {
        // use all principals in the keytab if a principal isn't specifically configured
        String[] principals;
        if (principal.equals("*")) {
            try {
                principals = KerberosUtil.getPrincipalNames(keytab, Pattern.compile("HTTP/.*"));
            } catch (IOException e) {
                throw new ConfigurationException(e);
            }
            if (principals.length == 0) {
                throw new ConfigurationException("Principals do not exist in the keytab");
            }
        } else {
            principals = new String[] {principal};
        }
        return principals;
    }
}
