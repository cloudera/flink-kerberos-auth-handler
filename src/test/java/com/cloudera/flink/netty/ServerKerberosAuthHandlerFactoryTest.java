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
import org.apache.flink.util.ConfigurationException;

import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static com.cloudera.flink.config.KerberosAuthOptions.SECURITY_SPNEGO_KEYTAB;
import static com.cloudera.flink.config.KerberosAuthOptions.SECURITY_SPNEGO_PRINCIPAL;
import static com.cloudera.flink.config.KerberosAuthOptions.SPNEGO_AUTH_ENABLED;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServerKerberosAuthHandlerFactoryTest {

    @Test
    public void validatesHttpPrincipal() throws ConfigurationException {
        Configuration conf = new Configuration();
        conf.set(SPNEGO_AUTH_ENABLED, true);
        conf.set(SECURITY_SPNEGO_PRINCIPAL, "HTTP/node-1.example.com@EXAMPLE.ORG");
        conf.set(
                SECURITY_SPNEGO_KEYTAB,
                ServerKerberosAuthHandlerFactoryTest.class.getResource("/test.keytab").getFile());
        ServerKerberosAuthHandlerFactory factory = new ServerKerberosAuthHandlerFactory();
        assertTrue(factory.createHandler(conf, new HashMap<>()).isPresent());
    }

    @Test
    public void validatesWildcardPrincipal() throws ConfigurationException {
        Configuration conf = new Configuration();
        conf.set(SPNEGO_AUTH_ENABLED, true);
        conf.set(SECURITY_SPNEGO_PRINCIPAL, "*");
        conf.set(
                SECURITY_SPNEGO_KEYTAB,
                ServerKerberosAuthHandlerFactoryTest.class.getResource("/test.keytab").getFile());
        ServerKerberosAuthHandlerFactory factory = new ServerKerberosAuthHandlerFactory();
        assertTrue(factory.createHandler(conf, new HashMap<>()).isPresent());
    }

    @Test
    public void throwsOnNonHttpPrincipal() {
        Configuration conf = new Configuration();
        conf.set(SPNEGO_AUTH_ENABLED, true);
        conf.set(SECURITY_SPNEGO_PRINCIPAL, "test/node-1.example.com@EXAMPLE.ORG");
        conf.set(
                SECURITY_SPNEGO_KEYTAB,
                ServerKerberosAuthHandlerFactoryTest.class.getResource("/test.keytab").getFile());
        ServerKerberosAuthHandlerFactory factory = new ServerKerberosAuthHandlerFactory();
        assertThrows(
                ConfigurationException.class, () -> factory.createHandler(conf, new HashMap<>()));
    }
}
