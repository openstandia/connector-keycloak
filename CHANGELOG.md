# [2.0.0](https://github.com/openstandia/connector-keycloak/compare/v1.1.6...v2.0.0) (2026-05-09)


### Bug Fixes

* add configurable HTTP client timeouts to prevent hanging connections ([d5b4549](https://github.com/openstandia/connector-keycloak/commit/d5b4549a341346a3a63b7a0c1682f1add43c392e))
* add pagination, SearchResultsHandler and tests for Realm Role ([6e62bec](https://github.com/openstandia/connector-keycloak/commit/6e62becc9298fc0427676eb71fa838a25b483f07))
* adjust PR changes and add comprehensive test suite ([11cde19](https://github.com/openstandia/connector-keycloak/commit/11cde198913b00a9b7f49188f9b826d64ef0bd91))


* feat!: change ClientRole UID to clientUUID/roleId format ([d6505b3](https://github.com/openstandia/connector-keycloak/commit/d6505b38b0c17edab5dfddf8457d540e659a2351))


### Features

* add client role mapping for groups ([4b34374](https://github.com/openstandia/connector-keycloak/commit/4b343745916905fcc488282d4cdf96f132880d9e)), closes [#22](https://github.com/openstandia/connector-keycloak/issues/22)
* add client role mapping for users ([dbb851e](https://github.com/openstandia/connector-keycloak/commit/dbb851e39190c454989e0d7f0217dc9931f76319))
* add realm role mapping for groups ([7ba68db](https://github.com/openstandia/connector-keycloak/commit/7ba68dbf2b2db010f58cfcd4174c302ca2b2939d))
* add Realm Role support ([0612cb0](https://github.com/openstandia/connector-keycloak/commit/0612cb0c901e60e06c86ae5b4feabde8225fe59b)), closes [#24](https://github.com/openstandia/connector-keycloak/issues/24)
* add requiredActions attribute for users ([01bd1bc](https://github.com/openstandia/connector-keycloak/commit/01bd1bc44a83b21c158eeecad886c3eae384953e))
* upgrade to Keycloak 26 and ConnId 1.6 with MidPoint pagination fixes ([4e5bfde](https://github.com/openstandia/connector-keycloak/commit/4e5bfdeaf503e20b5485b1bdce1928353d9d9998))


### BREAKING CHANGES

* ClientRole UID changed from roleId to clientUUID/roleId.
User/Group clientRoles attribute now uses clientUUID/roleId format to match
ClientRole UID for proper MidPoint association support.
Existing MidPoint shadows for clientRole objects need to be refreshed
by running a reconciliation task after upgrading.
