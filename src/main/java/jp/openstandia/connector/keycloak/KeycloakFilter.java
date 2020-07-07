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

import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;

/**
 * Filter for keycloak query.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakFilter {
    public final Uid uid;
    public final Name name;

    private KeycloakFilter(Uid uid) {
        this.uid = uid;
        this.name = null;
    }

    private KeycloakFilter(Name name) {
        this.uid = null;
        this.name = name;
    }

    public static KeycloakFilter By(Uid uid) {
        return new KeycloakFilter(uid);
    }

    public static KeycloakFilter By(Name name) {
        return new KeycloakFilter(name);
    }

    public boolean isByUid() {
        return uid != null;
    }

    public boolean isByName() {
        return name != null;
    }
}
