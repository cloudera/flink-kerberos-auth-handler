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
package com.cloudera.flink.config;

import org.apache.flink.annotation.docs.Documentation;
import org.apache.flink.configuration.ConfigOption;

import static org.apache.flink.configuration.ConfigOptions.key;

/** The set of configuration options relating to kerberos authentication. */
public class KerberosAuthOptions {
    @Documentation.Section(Documentation.Sections.SECURITY_AUTH_KERBEROS)
    public static final ConfigOption<Boolean> SPNEGO_AUTH_ENABLED =
            key("security.spnego.auth.enabled")
                    .booleanType()
                    .defaultValue(false)
                    .withDescription("Turns on/off SPNEGO authentication.");

    @Documentation.Section(Documentation.Sections.SECURITY_AUTH_KERBEROS)
    public static final ConfigOption<String> SECURITY_SPNEGO_PRINCIPAL =
            key("security.spnego.auth.principal")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Kerberos principal for SPNEGO name associated with the keytab.");

    @Documentation.Section(Documentation.Sections.SECURITY_AUTH_KERBEROS)
    public static final ConfigOption<String> SECURITY_SPNEGO_KEYTAB =
            key("security.spnego.auth.keytab")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Absolute path to a Kerberos keytab file that contains the credentials for SPNEGO.");
}
