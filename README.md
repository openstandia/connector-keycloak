# Keycloak Connector

## Description

[MidPoint](https://github.com/Evolveum/midpoint) Connector for [Keycloak](https://keycloak.org).

## Capabilities and Features

* Schema: YES
* Provisioning: YES
* Live Synchronization: No
* Password: YES
* Activation: YES
* Script execution: No 

This connector contains support for Keycloak user and group.

## Automated Test Matrix

Integration tests are run against the following Keycloak versions in CI:

| Keycloak |
|----------|
| 24.0.5   |
| 26.0.8   |
| 26.6.1   |

E2E tests verify connector deployment on the following MidPoint versions:

| MidPoint |
|----------|
| 4.0.4    |
| 4.4.11   |
| 4.8.11   |
| 4.10.2   |

## Build

Install JDK 11+ and [maven3](https://maven.apache.org/download.cgi) then build:

```
mvn install
```

After successful the build, you can find `connector-keycloak-*.jar` in `target` directory.

## License

Licensed under the [Apache License 2.0](/LICENSE).
