/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.federation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.client.AbstractReadOnlyClientStorageAdapter;
import org.keycloak.storage.client.ClientLookupProvider;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.storage.client.ClientStorageProviderModel;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class HardcodedClientStorageProvider implements ClientStorageProvider, ClientLookupProvider {
    protected KeycloakSession session;
    protected ClientStorageProviderModel component;
    protected String clientId;
    protected String redirectUri;
    protected boolean consent;

    public HardcodedClientStorageProvider(KeycloakSession session, ClientStorageProviderModel component) {
        this.session = session;
        this.component = component;
        this.clientId = component.getConfig().getFirst(HardcodedClientStorageProviderFactory.CLIENT_ID);
        this.redirectUri = component.getConfig().getFirst(HardcodedClientStorageProviderFactory.REDIRECT_URI);
        this.consent = "true".equals(component.getConfig().getFirst(HardcodedClientStorageProviderFactory.CONSENT));
    }

    @Override
    public ClientModel getClientById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        final String clientId = storageId.getExternalId();
        if (this.clientId.equals(clientId)) return new ClientAdapter(realm);
        return null;
    }

    @Override
    public ClientModel getClientByClientId(String clientId, RealmModel realm) {
        if (this.clientId.equals(clientId)) return new ClientAdapter(realm);
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public List<ClientModel> searchClientsByClientId(String clientId, Integer firstResult, Integer maxResults, RealmModel realm) {
        if (clientId != null && this.clientId.toLowerCase().contains(clientId.toLowerCase())) {
            return Collections.singletonList(new ClientAdapter(realm));
        }
        return Collections.EMPTY_LIST;
    }

    public class ClientAdapter extends AbstractReadOnlyClientStorageAdapter {

        public ClientAdapter(RealmModel realm) {
            super(HardcodedClientStorageProvider.this.session, realm, HardcodedClientStorageProvider.this.component);
        }

        @Override
        public String getClientId() {
            return clientId;
        }

        @Override
        public String getName() {
            return "Federated Client";
        }

        @Override
        public String getDescription() {
            return "Pulled in from client storage provider";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public boolean isAlwaysDisplayInConsole() {
            return false;
        }

        @Override
        public Set<String> getWebOrigins() {
            return Collections.EMPTY_SET;
        }

        @Override
        public Set<String> getRedirectUris() {
            HashSet<String> set = new HashSet<>();
            set.add(redirectUri);
            return set;
        }

        @Override
        public String getManagementUrl() {
            return null;
        }

        @Override
        public String getRootUrl() {
            return null;
        }

        @Override
        public String getBaseUrl() {
            return null;
        }

        @Override
        public boolean isBearerOnly() {
            return false;
        }

        @Override
        public int getNodeReRegistrationTimeout() {
            return 0;
        }

        @Override
        public String getClientAuthenticatorType() {
            return null;
        }

        @Override
        public boolean validateSecret(String secret) {
            return "password".equals(secret);
        }

        @Override
        public String getSecret() {
            return "password";
        }

        @Override
        public String getRegistrationToken() {
            return null;
        }

        @Override
        public String getProtocol() {
            return "openid-connect";
        }

        @Override
        public String getAttribute(String name) {
            return null;
        }

        @Override
        public Map<String, String> getAttributes() {
            return Collections.EMPTY_MAP;
        }

        @Override
        public String getAuthenticationFlowBindingOverride(String binding) {
            return null;
        }

        @Override
        public Map<String, String> getAuthenticationFlowBindingOverrides() {
            return Collections.EMPTY_MAP;
        }

        @Override
        public boolean isFrontchannelLogout() {
            return false;
        }

        @Override
        public boolean isPublicClient() {
            return false;
        }

        @Override
        public boolean isConsentRequired() {
            return consent;
        }

        @Override
        public boolean isStandardFlowEnabled() {
            return true;
        }

        @Override
        public boolean isImplicitFlowEnabled() {
            return true;
        }

        @Override
        public boolean isDirectAccessGrantsEnabled() {
            return true;
        }

        @Override
        public boolean isServiceAccountsEnabled() {
            return false;
        }

        @Override
        public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope, boolean filterByProtocol) {
            if (defaultScope) {
                ClientScopeModel rolesScope = KeycloakModelUtils.getClientScopeByName(realm, OIDCLoginProtocolFactory.ROLES_SCOPE);
                ClientScopeModel webOriginsScope = KeycloakModelUtils.getClientScopeByName(realm, OIDCLoginProtocolFactory.WEB_ORIGINS_SCOPE);
                return Arrays.asList(rolesScope, webOriginsScope)
                        .stream()
                        .collect(Collectors.toMap(ClientScopeModel::getName, clientScope -> clientScope));

            } else {
                ClientScopeModel offlineScope = KeycloakModelUtils.getClientScopeByName(realm, "offline_access");
                return Collections.singletonMap("offline_access", offlineScope);
            }
        }

        @Override
        public int getNotBefore() {
            return 0;
        }

        @Override
        public Set<ProtocolMapperModel> getProtocolMappers() {
            return Collections.EMPTY_SET;
        }

        @Override
        public ProtocolMapperModel getProtocolMapperById(String id) {
            return null;
        }

        @Override
        public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
            return null;
        }

        @Override
        public boolean isFullScopeAllowed() {
            return false;
        }

        @Override
        public Set<RoleModel> getScopeMappings() {
            RoleModel offlineAccess = realm.getRole("offline_access");
            Set<RoleModel> set = new HashSet<>();
            set.add(offlineAccess);
            return set;
        }

        @Override
        public Set<RoleModel> getRealmScopeMappings() {
            return Collections.EMPTY_SET;
        }

        @Override
        public boolean hasScope(RoleModel role) {
            return false;
        }
    }


}
