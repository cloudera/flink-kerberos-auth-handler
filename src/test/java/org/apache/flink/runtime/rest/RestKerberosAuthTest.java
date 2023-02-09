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
package org.apache.flink.runtime.rest;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.RestOptions;
import org.apache.flink.configuration.SecurityOptions;
import org.apache.flink.core.testutils.CommonTestUtils;
import org.apache.flink.runtime.rest.util.TestRestServerEndpoint;
import org.apache.flink.runtime.rpc.RpcUtils;
import org.apache.flink.runtime.webmonitor.RestfulGateway;
import org.apache.flink.runtime.webmonitor.TestingRestfulGateway;

import com.cloudera.flink.config.KerberosAuthOptions;
import org.apache.hadoop.minikdc.KerberosSecurityTestcase;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.junit.BeforeClass;
import org.junit.Test;
import sun.security.krb5.KrbAsReqBuilder;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.internal.ccache.Credentials;
import sun.security.krb5.internal.ccache.CredentialsCache;

import javax.security.auth.kerberos.KeyTab;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** This test validates Kerberos authentication for rest endpoints. */
public class RestKerberosAuthTest {

    private static final String SERVER_HOST = "localhost";
    private static final String SERVER_PRINCIPAL_ID = "HTTP/" + SERVER_HOST;
    private static final String CLIENT_PRINCIPAL_ID = "client";
    private static final String REALM = "EXAMPLE.COM";

    private static final String SERVER_PRINCIPAL = SERVER_PRINCIPAL_ID + "@" + REALM;
    private static final String CLIENT_PRINCIPAL = CLIENT_PRINCIPAL_ID + "@" + REALM;
    private static final String KEYTAB_FILE =
            new File(System.getProperty("test.dir", "target"), UUID.randomUUID().toString())
                    .getAbsolutePath();
    private static final String TICKET_CACHE_FILE =
            new File(System.getProperty("test.dir", "target"), UUID.randomUUID().toString())
                    .getAbsolutePath();

    private static RestServerEndpoint serverEndpoint;
    private static RestServerEndpointITCase.TestVersionHandler testVersionHandler;

    private final Executor testExecutor = Executors.newSingleThreadExecutor();

    @BeforeClass
    public static void init() throws Exception {
        KerberosSecurityTestcase mockKerberos = new KerberosSecurityTestcase();
        mockKerberos.startMiniKdc();
        File keytabFile = new File(KEYTAB_FILE);
        mockKerberos.getKdc().createPrincipal(keytabFile, CLIENT_PRINCIPAL_ID, SERVER_PRINCIPAL_ID);

        PrincipalName clientPrincipalName =
                new PrincipalName(CLIENT_PRINCIPAL, PrincipalName.KRB_NT_PRINCIPAL, null);
        KrbAsReqBuilder builder =
                new KrbAsReqBuilder(clientPrincipalName, KeyTab.getInstance(new File(KEYTAB_FILE)));
        builder.setTarget(PrincipalName.tgsService(REALM, REALM));
        builder.action();
        Credentials credentials = builder.getCCreds();
        builder.destroy();

        CredentialsCache cache = CredentialsCache.create(clientPrincipalName, TICKET_CACHE_FILE);
        assertNotNull(cache);
        cache.update(credentials);
        cache.save();

        KerberosName.setRules("DEFAULT");
        Configuration serverConfig = getServerConfig();
        RestServerEndpointConfiguration restServerConfig =
                RestServerEndpointConfiguration.fromConfiguration(serverConfig);

        RestfulGateway restfulGateway = new TestingRestfulGateway.Builder().build();
        testVersionHandler =
                new RestServerEndpointITCase.TestVersionHandler(
                        () -> CompletableFuture.completedFuture(restfulGateway),
                        RpcUtils.INF_TIMEOUT);

        serverEndpoint =
                TestRestServerEndpoint.builder(serverConfig)
                        .withHandler(testVersionHandler.getMessageHeaders(), testVersionHandler)
                        .build();
        serverEndpoint.start();
    }

    @Test
    public void testAuthSuccessfulWithTicketCache() throws Exception {
        Configuration goodCredsConf = getClientConfig();

        RestClient restClientWithGoodCredentials = new RestClient(goodCredsConf, testExecutor);
        final Map<String, String> oldEnv = System.getenv();
        try {
            Map<String, String> env = new HashMap<>(1);
            env.put("KRB5CCNAME", TICKET_CACHE_FILE);
            CommonTestUtils.setEnv(env);

            restClientWithGoodCredentials
                    .sendRequest(
                            SERVER_HOST,
                            serverEndpoint.getServerAddress().getPort(),
                            testVersionHandler.getMessageHeaders())
                    .get();
        } finally {
            CommonTestUtils.setEnv(oldEnv);
        }
    }

    @Test
    public void testAuthSuccessfulWithKeytab() throws Exception {
        Configuration goodCredsConf = getClientConfig();
        goodCredsConf.set(SecurityOptions.KERBEROS_LOGIN_KEYTAB, KEYTAB_FILE);
        goodCredsConf.set(SecurityOptions.KERBEROS_LOGIN_PRINCIPAL, CLIENT_PRINCIPAL);

        RestClient restClientWithGoodCredentials = new RestClient(goodCredsConf, testExecutor);
        restClientWithGoodCredentials
                .sendRequest(
                        SERVER_HOST,
                        serverEndpoint.getServerAddress().getPort(),
                        testVersionHandler.getMessageHeaders())
                .get();
    }

    @Test
    public void testNoCreds() throws Exception {
        Configuration noCredsConf = getClientConfig();
        noCredsConf.set(KerberosAuthOptions.SPNEGO_AUTH_ENABLED, false);

        RestClient restClientWithBadCredentials = new RestClient(noCredsConf, testExecutor);

        try {
            restClientWithBadCredentials
                    .sendRequest(
                            SERVER_HOST,
                            serverEndpoint.getServerAddress().getPort(),
                            testVersionHandler.getMessageHeaders())
                    .get();
            fail();
        } catch (ExecutionException ee) {
            assertTrue(ee.getCause().getMessage().contains("Missing authorization header"));
        }
    }

    private static Configuration getServerConfig() {
        final Configuration conf = new Configuration();
        conf.setString(RestOptions.ADDRESS, SERVER_HOST);
        conf.set(KerberosAuthOptions.SPNEGO_AUTH_ENABLED, true);
        conf.set(KerberosAuthOptions.SECURITY_SPNEGO_KEYTAB, KEYTAB_FILE);
        conf.set(KerberosAuthOptions.SECURITY_SPNEGO_PRINCIPAL, SERVER_PRINCIPAL);
        return conf;
    }

    private static Configuration getClientConfig() {
        final Configuration conf = new Configuration();
        conf.setLong(RestOptions.IDLENESS_TIMEOUT, 5000L);
        conf.set(KerberosAuthOptions.SPNEGO_AUTH_ENABLED, true);
        return conf;
    }
}
