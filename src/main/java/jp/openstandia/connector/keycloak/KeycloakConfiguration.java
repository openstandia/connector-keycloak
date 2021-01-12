/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * Connector Configuration implementation for keycloak connector.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakConfiguration extends AbstractConfiguration {

    private String serverUrl;
    private String username;
    private GuardedString password;
    private String clientId;
    private GuardedString clientSecret;
    private String realmName;
    private String targetRealmName;
    private String userAttributes;
    private String groupAttributes;
    private String clientAttributes;
    private int queryPageSize;
    private boolean passwordResetAPIEnabled;
    private boolean grpcEnabled;
    private String grpcHost;
    private int grpcPort;

    private String httpProxyHost;
    private int httpProxyPort;
    private String httpProxyUser;
    private GuardedString httpProxyPassword;

    @ConfigurationProperty(
            order = 1,
            displayMessageKey = "Keycloak Server URL",
            helpMessageKey = "Keycloak Server URL (ex. https://mykeycloak/auth).",
            required = true,
            confidential = false)
    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    @ConfigurationProperty(
            order = 2,
            displayMessageKey = "Username",
            helpMessageKey = "Set the username to connect the keycloak server. " +
                    "This option will be used when you want to use grant_type=password mode.",
            required = false,
            confidential = false)
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @ConfigurationProperty(
            order = 3,
            displayMessageKey = "Password",
            helpMessageKey = "Set the password to connect the keycloak server. " +
                    "This option will be used when you want to use grant_type=password mode.",
            required = false,
            confidential = true)
    public GuardedString getPassword() {
        return password;
    }

    public void setPassword(GuardedString password) {
        this.password = password;
    }

    @ConfigurationProperty(
            order = 4,
            displayMessageKey = "Client ID",
            helpMessageKey = "Set the client ID to connect the keycloak server.",
            required = true,
            confidential = false)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @ConfigurationProperty(
            order = 5,
            displayMessageKey = "Client Secret",
            helpMessageKey = "Set the client secret to connect the keycloak server. " +
                    "This option will be used when you want to use grant_type=client_credentials mode.",
            required = false,
            confidential = true)
    public GuardedString getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(GuardedString clientSecret) {
        this.clientSecret = clientSecret;
    }

    @ConfigurationProperty(
            order = 6,
            displayMessageKey = "Realm Name",
            helpMessageKey = "Realm name which is used for the client authentication.",
            required = true,
            confidential = false)
    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    @ConfigurationProperty(
            order = 7,
            displayMessageKey = "Target Realm Name",
            helpMessageKey = "Target realm name which is used for the connector operations.",
            required = true,
            confidential = false)
    public String getTargetRealmName() {
        return targetRealmName;
    }

    public void setTargetRealmName(String targetRealmName) {
        this.targetRealmName = targetRealmName;
    }

    @ConfigurationProperty(
            order = 8,
            displayMessageKey = "User Attributes",
            helpMessageKey = "Keycloak user attributes (comma-separated). Use :multivalued suffix for multiple value.",
            required = false,
            confidential = false)
    public String getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(String userAttributes) {
        this.userAttributes = userAttributes;
    }

    @ConfigurationProperty(
            order = 9,
            displayMessageKey = "Group Attributes",
            helpMessageKey = "Keycloak group attributes (comma-separated). Use :multivalued suffix for multiple value.",
            required = false,
            confidential = false)
    public String getGroupAttributes() {
        return groupAttributes;
    }

    public void setGroupAttributes(String groupAttributes) {
        this.groupAttributes = groupAttributes;
    }

    @ConfigurationProperty(
            order = 10,
            displayMessageKey = "Client Attributes",
            helpMessageKey = "Keycloak client attributes (comma-separated).",
            required = false,
            confidential = false)
    public String getClientAttributes() {
        return clientAttributes;
    }

    public void setClientAttributes(String clientAttributes) {
        this.clientAttributes = clientAttributes;
    }

    @ConfigurationProperty(
            order = 11,
            displayMessageKey = "Query Page Size",
            helpMessageKey = "Page size of search query in the connector. Default is 100.",
            required = false,
            confidential = false)
    public int getQueryPageSize() {
        if (queryPageSize <= 0) {
            return 100;
        }
        return queryPageSize;
    }

    public void setQueryPageSize(int queryPageSize) {
        this.queryPageSize = queryPageSize;
    }

    @ConfigurationProperty(
            order = 12,
            displayMessageKey = "Enable Password Reset API for update password",
            helpMessageKey = "If yes, the connector uses password reset API instead of create/update user API. " +
                    "Pros. The raw password isn't recorded in the Keycloak admin event. " +
                    "Cons. The operation for update password is executed separately.",
            required = false,
            confidential = false)
    public boolean isPasswordResetAPIEnabled() {
        return passwordResetAPIEnabled;
    }

    public void setPasswordResetAPIEnabled(boolean passwordResetAPIEnabled) {
        this.passwordResetAPIEnabled = passwordResetAPIEnabled;
    }

    @ConfigurationProperty(
            order = 13,
            displayMessageKey = "Enable gRPC",
            helpMessageKey = "Enable gRPC for the Keycloak API. CAUTION: You need to install keycloak-grpc on the Keycloak server.",
            required = false,
            confidential = false)
    public boolean isGrpcEnabled() {
        return grpcEnabled;
    }

    public void setGrpcEnabled(boolean grpcEnabled) {
        this.grpcEnabled = grpcEnabled;
    }

    @ConfigurationProperty(
            order = 14,
            displayMessageKey = "gRPC Host",
            helpMessageKey = "Hostname for gRPC connection.",
            required = false,
            confidential = false)
    public String getGrpcHost() {
        return grpcHost;
    }

    public void setGrpcHost(String grpcHost) {
        this.grpcHost = grpcHost;
    }

    @ConfigurationProperty(
            order = 15,
            displayMessageKey = "gRPC Port",
            helpMessageKey = "Port for gRPC connection.",
            required = false,
            confidential = false)
    public int getGrpcPort() {
        return grpcPort;
    }

    public void setGrpcPort(int grpcHost) {
        this.grpcPort = grpcPort;
    }

    @ConfigurationProperty(
            order = 16,
            displayMessageKey = "HTTP Proxy Host",
            helpMessageKey = "Hostname for the HTTP Proxy",
            required = false,
            confidential = false)
    public String getHttpProxyHost() {
        return httpProxyHost;
    }

    public void setHttpProxyHost(String httpProxyHost) {
        this.httpProxyHost = httpProxyHost;
    }

    @ConfigurationProperty(
            order = 17,
            displayMessageKey = "HTTP Proxy Port",
            helpMessageKey = "Port for the HTTP Proxy",
            required = false,
            confidential = false)
    public int getHttpProxyPort() {
        return httpProxyPort;
    }

    public void setHttpProxyPort(int httpProxyPort) {
        this.httpProxyPort = httpProxyPort;
    }

    @ConfigurationProperty(
            order = 18,
            displayMessageKey = "HTTP Proxy User",
            helpMessageKey = "Username for the HTTP Proxy Authentication",
            required = false,
            confidential = false)
    public String getHttpProxyUser() {
        return httpProxyUser;
    }

    public void setHttpProxyUser(String httpProxyUser) {
        this.httpProxyUser = httpProxyUser;
    }

    @ConfigurationProperty(
            order = 19,
            displayMessageKey = "HTTP Proxy Password",
            helpMessageKey = "Password for the HTTP Proxy Authentication",
            required = false,
            confidential = true)
    public GuardedString getHttpProxyPassword() {
        return httpProxyPassword;
    }

    public void setHttpProxyPassword(GuardedString httpProxyPassword) {
        this.httpProxyPassword = httpProxyPassword;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(getUsername()) || getPassword() == null && getClientSecret() == null) {
            throw new ConfigurationException("Invalid client credential: need to setup username/password or client secret.");
        }
    }
}
