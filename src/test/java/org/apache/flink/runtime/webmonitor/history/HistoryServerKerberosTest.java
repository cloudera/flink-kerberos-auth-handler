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
package org.apache.flink.runtime.webmonitor.history;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.HistoryServerOptions;
import org.apache.flink.test.util.SecureTestEnvironment;

import com.cloudera.flink.config.KerberosAuthOptions;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;

/** Test for the HistoryServer Kerberos integration. */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HistoryServerKerberosTest {

    @Rule public final TemporaryFolder secureEnvironmentBaseFolder = new TemporaryFolder();
    @Rule public final TemporaryFolder historyServerBaseFolder = new TemporaryFolder();

    private File jmDirectory;
    private String servicePrincipal;

    @Before
    public void setUp() throws Exception {
        String principal = "HTTP/" + SecureTestEnvironment.HOST_NAME;
        SecureTestEnvironment.prepare(secureEnvironmentBaseFolder, principal);
        servicePrincipal = principal + "@" + SecureTestEnvironment.getRealm();
        jmDirectory = historyServerBaseFolder.newFolder("jm");
    }

    @After
    public void tearDown() {
        SecureTestEnvironment.cleanup();
    }

    // Success test MUST be executed before no credential tests, please see:
    // https://gist.github.com/gaborgsomogyi/8092c9be8ac65b62baa00ccf3f344e67
    @Test
    public void testAuthSuccessful() throws Exception {
        Configuration serverConfig = getServerConfig();
        HistoryServer hs = new HistoryServer(serverConfig);

        try {
            hs.start();
            String baseUrl = "http://localhost:" + hs.getWebPort();
            Assert.assertEquals(200, getHTTPResponseCode(baseUrl));
        } finally {
            hs.stop();
        }
    }

    @Test
    public void testNoCreds() throws Exception {
        Configuration serverConfig = getServerConfig();
        HistoryServer hs = new HistoryServer(serverConfig);
        javax.security.auth.login.Configuration.setConfiguration(null);

        try {
            hs.start();
            String baseUrl = "http://localhost:" + hs.getWebPort();
            Assert.assertEquals(401, getHTTPResponseCode(baseUrl));
        } finally {
            hs.stop();
        }
    }

    private Configuration getServerConfig() {
        Configuration config = new Configuration();
        config.setString(
                HistoryServerOptions.HISTORY_SERVER_ARCHIVE_DIRS, jmDirectory.toURI().toString());
        config.setBoolean(KerberosAuthOptions.SPNEGO_AUTH_ENABLED, true);
        config.setString(
                KerberosAuthOptions.SECURITY_SPNEGO_KEYTAB, SecureTestEnvironment.getTestKeytab());
        config.setString(KerberosAuthOptions.SECURITY_SPNEGO_PRINCIPAL, servicePrincipal);
        return config;
    }

    private int getHTTPResponseCode(String url) throws Exception {
        URL u = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) u.openConnection();
        connection.setConnectTimeout(100000);
        connection.connect();
        return connection.getResponseCode();
    }
}
