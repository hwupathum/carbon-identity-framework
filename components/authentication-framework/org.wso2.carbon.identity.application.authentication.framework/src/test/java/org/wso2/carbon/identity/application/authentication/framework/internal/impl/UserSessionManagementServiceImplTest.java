/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.internal.impl;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.UserSessionDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.internal.util.SessionEventPublishingUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.services.SessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.SessionMgtConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for UserSessionManagementServiceImpl.
 */
@WithCarbonHome
public class UserSessionManagementServiceImplTest {

    @Mock
    private FrameworkServiceDataHolder frameworkServiceDataHolder;

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @Mock
    private UserSessionStore userSessionStore;

    @Mock
    private FederatedAssociationManager federatedAssociationManager;

    @Mock
    private SessionContext sessionContext;

    @Mock
    private SessionManagementService sessionManagementService;

    @Mock
    private IdpManager idpManager;

    @Mock
    private IdentityProvider identityProvider;

    private UserSessionManagementServiceImpl userSessionManagementService;
    private MockedStatic<FrameworkServiceDataHolder> frameworkServiceDataHolderMockedStatic;
    private MockedStatic<UserSessionStore> userSessionStoreMockedStatic;
    private MockedStatic<IdentityUtil> identityUtilMockedStatic;
    private Map<SessionMgtConstants.AuthSessionUserKeys, String> authSessionUserMap = new HashMap<>();

    private static final String TEST_TENANT_DOMAIN = "test-tenant.com";
    private static final int TEST_TENANT_ID = 1;
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_FED_USER_ID = "test-fed-user-id";
    private static final String TEST_SESSION_ID_1 = "test-session-id-1";
    private static final String TEST_SESSION_ID_2 = "test-session-id-2";
    private static final String TEST_IDP_ID = "1";
    private static final String TEST_IDP_NAME = "LOCAL";

    @BeforeClass
    public void setUp() throws Exception {

        openMocks(this);

        frameworkServiceDataHolderMockedStatic = mockStatic(FrameworkServiceDataHolder.class);
        userSessionStoreMockedStatic = mockStatic(UserSessionStore.class);
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);

        frameworkServiceDataHolderMockedStatic.when(FrameworkServiceDataHolder::getInstance)
                .thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(frameworkServiceDataHolder.getFederatedAssociationManager()).thenReturn(federatedAssociationManager);
        when(frameworkServiceDataHolder.getIdentityProviderManager()).thenReturn(idpManager);
        when(idpManager.getResidentIdP(TEST_TENANT_DOMAIN)).thenReturn(identityProvider);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserNameFromUserID(anyString())).thenReturn("PRIMARY/test-user");
        when(sessionContext.getProperties()).thenReturn(new HashMap<>());
        when(federatedAssociationManager.getFederatedAssociationsOfUser(anyInt(), anyString(), anyString()))
                .thenReturn(new ArrayList<>());

        userSessionManagementService = new UserSessionManagementServiceImpl();
        userSessionStoreMockedStatic.when(UserSessionStore::getInstance).thenReturn(userSessionStore);
        authSessionUserMap.put(SessionMgtConstants.AuthSessionUserKeys.USER_ID, TEST_FED_USER_ID);
        authSessionUserMap.put(SessionMgtConstants.AuthSessionUserKeys.IDP_ID, TEST_IDP_ID);
        authSessionUserMap.put(SessionMgtConstants.AuthSessionUserKeys.IDP_NAME, TEST_IDP_NAME);
    }

    @AfterClass
    public void tearDown() {

        frameworkServiceDataHolderMockedStatic.close();
        userSessionStoreMockedStatic.close();
        identityUtilMockedStatic.close();
    }

    @Test
    public void testAddAssociatedAssociatedLocalUserIdSessionsWithFilterDisabled() throws Exception {

        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(FrameworkConstants.FILER_BY_SESSION_ID_FOR_USER))
                .thenReturn("false");
        List<UserSession> userSessions = new ArrayList<>();
        userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
        setupFederatedUserSessionMocks(TEST_SESSION_ID_2, TEST_FED_USER_ID);

        Method method = getAddAssociatedAssociatedLocalUserIdSessionsMethod();
        executeWithCommonMocks(method, userSessions, TEST_FED_USER_ID, TEST_SESSION_ID_2);

        assertEquals(userSessions.size(), 2);
        assertTrue(userSessions.stream().anyMatch(session -> TEST_SESSION_ID_2.equals(session.getSessionId())));
    }

    @Test
    public void testAddAssociatedAssociatedLocalUserIdSessionsWithFilterEnabled() throws Exception {

        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(FrameworkConstants.FILER_BY_SESSION_ID_FOR_USER))
                .thenReturn("true");
        List<UserSession> userSessions = new ArrayList<>();
        userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
        setupFederatedUserSessionMocks(TEST_SESSION_ID_2, TEST_FED_USER_ID);

        Method method = getAddAssociatedAssociatedLocalUserIdSessionsMethod();
        executeWithCommonMocks(method, userSessions, TEST_FED_USER_ID, TEST_SESSION_ID_2);

        assertEquals(userSessions.size(), 2);
        UserSession actualSession = userSessions.stream()
                .filter(session -> TEST_SESSION_ID_2.equals(session.getSessionId()))
                .findFirst()
                .orElse(null);
        assertNotNull(actualSession);
    }

    @Test
    public void testAddAssociatedAssociatedLocalUserIdSessionsWithDuplicateSessionIdsWithFilterDisabled()
            throws Exception {

        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(FrameworkConstants.FILER_BY_SESSION_ID_FOR_USER))
                .thenReturn("false");
        List<UserSession> userSessions = new ArrayList<>();
        userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
        setupFederatedUserSessionMocks(TEST_SESSION_ID_1, TEST_FED_USER_ID);

        Method method = getAddAssociatedAssociatedLocalUserIdSessionsMethod();
        executeWithCommonMocks(method, userSessions, TEST_FED_USER_ID, TEST_SESSION_ID_1);

        assertEquals(userSessions.size(), 2);
    }

    @Test
    public void testAddAssociatedAssociatedLocalUserIdSessionsWithDuplicateSessionIdsWithFilterEnabled()
            throws Exception {

        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(FrameworkConstants.FILER_BY_SESSION_ID_FOR_USER))
                .thenReturn("true");
        List<UserSession> userSessions = new ArrayList<>();
        userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
        setupFederatedUserSessionMocks(TEST_SESSION_ID_1, TEST_FED_USER_ID);

        Method method = getAddAssociatedAssociatedLocalUserIdSessionsMethod();
        executeWithCommonMocks(method, userSessions, TEST_FED_USER_ID, TEST_SESSION_ID_1);

        assertEquals(userSessions.size(), 1);
        assertEquals(userSessions.get(0).getSessionId(), TEST_SESSION_ID_1);
    }

    @Test
    public void testAddAssociatedAssociatedLocalUserIdSessionsWithEmptyAuthSessionUserMap() throws Exception {

        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(FrameworkConstants.FILER_BY_SESSION_ID_FOR_USER))
                .thenReturn("false");
        List<UserSession> userSessions = new ArrayList<>();
        userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
        setupFederatedUserSessionMocks(TEST_SESSION_ID_2, TEST_FED_USER_ID);
        authSessionUserMap = new HashMap<>();

        Method method = getAddAssociatedAssociatedLocalUserIdSessionsMethod();
        executeWithCommonMocks(method, userSessions, TEST_FED_USER_ID, TEST_SESSION_ID_2);

        assertEquals(userSessions.size(), 2);
        assertTrue(userSessions.stream().anyMatch(session -> TEST_SESSION_ID_2.equals(session.getSessionId())));
    }

    private UserSession createTestUserSession(String sessionId, String userId) {

        UserSession userSession = new UserSession();
        userSession.setUserId(userId);
        userSession.setSessionId(sessionId);
        
        List<Application> applications = new ArrayList<>();
        Application app = new Application("subject", "Test App", "1");
        applications.add(app);
        userSession.setApplications(applications);
        
        return userSession;
    }

    private void setupFederatedUserSessionMocks(String sessionId, String userId) throws Exception {

        List<String> fedUserSessionIds = new ArrayList<>();
        fedUserSessionIds.add(sessionId);
        when(userSessionStore.getSessionId(userId)).thenReturn(fedUserSessionIds);
    }

    private Method getAddAssociatedAssociatedLocalUserIdSessionsMethod() throws Exception {

        Method method = UserSessionManagementServiceImpl.class.getDeclaredMethod(
                "addAssociatedAssociatedLocalUserIdSessions", List.class, String.class);
        method.setAccessible(true);
        return method;
    }

    private void executeWithCommonMocks(Method method, List<UserSession> userSessions, String fedUserId,
                                        String sessionId) throws Exception {

        UserSession fedUserSession = createTestUserSession(sessionId, fedUserId);

        // Mock session context
        SessionContext mockedSessionContext = mock(SessionContext.class);
        when(mockedSessionContext.getProperties()).thenReturn(new HashMap<>());

        try (MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
             MockedConstruction<UserSessionDAOImpl> userSessionDAOConstruction =
                     mockConstruction(UserSessionDAOImpl.class,
                             (mock, context) -> when(mock.getSession(sessionId)).thenReturn(fedUserSession))) {

            frameworkUtilsMockedStatic.when(() -> FrameworkUtils.getSessionContextFromCache(sessionId,
                    "carbon.super")).thenReturn(mockedSessionContext);
            frameworkUtilsMockedStatic.when(FrameworkUtils::getLoginTenantDomainFromContext).thenReturn("carbon.super");
            method.invoke(userSessionManagementService, userSessions, fedUserId);
        }
    }

    @Test
    public void testTerminateSessionsByUserIdWithSessionPreservingEnabled() throws Exception {

        List<String> sessionIds = new ArrayList<>();
        sessionIds.add(TEST_SESSION_ID_1);
        sessionIds.add(TEST_SESSION_ID_2);

        try (MockedStatic<CarbonContext> carbonContextMockedStatic = mockStatic(CarbonContext.class);
             MockedStatic<SessionEventPublishingUtil> sessionEventPublishingUtilMockedStatic =
                     mockStatic(SessionEventPublishingUtil.class)) {

            CarbonContext carbonContext = mock(CarbonContext.class);
            carbonContextMockedStatic.when(CarbonContext::getThreadLocalCarbonContext).thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

            identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(
                    FrameworkConstants.Config.PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE)).thenReturn("true");

            // Mock the IdentityProvider with OIDC federated authenticator config
            FederatedAuthenticatorConfig oidcConfig = mock(FederatedAuthenticatorConfig.class);
            when(oidcConfig.getName()).thenReturn(IdentityApplicationConstants.Authenticator.OIDC.NAME);
            
            Property preserveSessionProperty = mock(Property.class);
            when(preserveSessionProperty.getName()).thenReturn(
                    IdentityApplicationConstants.Authenticator.OIDC.PRESERVE_SESSION_AT_PASSWORD_UPDATE);
            when(preserveSessionProperty.getValue()).thenReturn("true");
            
            Property[] properties = new Property[]{preserveSessionProperty};
            when(oidcConfig.getProperties()).thenReturn(properties);
            FederatedAuthenticatorConfig[] authConfigs = new FederatedAuthenticatorConfig[]{oidcConfig};
            when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(authConfigs);

            Map<String, Object> threadLocalProperties = new HashMap<>();
            threadLocalProperties.put(FrameworkConstants.CURRENT_SESSION_IDENTIFIER, TEST_SESSION_ID_1);
            IdentityUtil.threadLocalProperties.set(threadLocalProperties);

            List<UserSession> userSessions = new ArrayList<>();
            userSessions.add(createTestUserSession(TEST_SESSION_ID_1, TEST_USER_ID));
            userSessions.add(createTestUserSession(TEST_SESSION_ID_2, TEST_USER_ID));

            UserSessionManagementServiceImpl service = spy(createSpyServiceWithSessionManagement());
            doReturn(userSessions).when(service).getSessionsByUserId(TEST_USER_ID);

            boolean result = service.terminateSessionsByUserId(TEST_USER_ID);

            assertTrue(result);
            // Only one session should be terminated (not the current one).
            verify(sessionManagementService, times(1)).removeSession(TEST_SESSION_ID_2);
            verify(userSessionStore, times(1)).removeTerminatedSessionRecords(anyList());
        } finally {
            IdentityUtil.threadLocalProperties.remove();
        }
    }

    private UserSessionManagementServiceImpl createSpyServiceWithSessionManagement() throws Exception {

        UserSessionManagementServiceImpl service = new UserSessionManagementServiceImpl();
        java.lang.reflect.Field sessionManagementServiceField =
                UserSessionManagementServiceImpl.class.getDeclaredField("sessionManagementService");
        sessionManagementServiceField.setAccessible(true);
        sessionManagementServiceField.set(service, sessionManagementService);

        return service;
    }
}
