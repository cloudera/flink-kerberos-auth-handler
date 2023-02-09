# Flink kerberos authentication handler

It implements custom netty HTTP request inbound/outbound handlers to add kerberos
authentication possibility to Flink.
Please see [FLIP-181](https://cwiki.apache.org/confluence/x/CAUBCw) for further details.

## How to build
In order to build the project one needs maven and java.
Since the authentication handler is Flink version dependent please make sure the version are matching in `pom.xml`.
```
mvn clean install
```

## How to install
* Make sure the following provided dependencies are available on the cluster:
    * `flink-runtime`
    * `hadoop-common`
    * `hadoop-auth`
* Add the following jar to the classpath:
```
target/flink-kerberos-auth-handler-<VERSION>.jar
```
As described in the mentioned implementation proposal Flink loads all
inbound/outbound handlers with service loader automatically.

## How to configure

The following configuration properties are supported:

Property | Type | Default | Description
---------|------|---------|------------
security.spnego.auth.enabled | boolean | false | Turns on/off SPNEGO authentication
security.spnego.auth.principal | string | (none) | Kerberos principal for SPNEGO name associated with the keytab
security.spnego.auth.keytab | string | (none) | Absolute path to a Kerberos keytab file that contains the credentials for SPNEGO

## License
This is licensed under Apache License Version 2.0.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
