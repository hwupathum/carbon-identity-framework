/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.core.dao;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.database.utils.jdbc.NamedPreparedStatement;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.CertificateRetriever;
import org.wso2.carbon.identity.core.CertificateRetrievingException;
import org.wso2.carbon.identity.core.DatabaseCertificateRetriever;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.KeyStoreCertificateRetriever;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.Tenant;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.core.util.JdbcUtils.isH2DB;

public class SAMLSSOServiceProviderDAOImpl implements SAMLSSOServiceProviderDAO {

    private static Log log = LogFactory.getLog(SAMLSSOServiceProviderDAOImpl.class);
    private final int tenantId;

    private final String tenantUUID;

    private static final String CERTIFICATE_PROPERTY_NAME = "CERTIFICATE";
    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID = "SELECT " +
            "META.VALUE FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 = "SELECT " +
            "META.`VALUE` FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    public SAMLSSOServiceProviderDAOImpl(int tenantId) {

        this.tenantId = tenantId;
        this.tenantUUID = getTenantUUID(tenantId);
    }

    @Override
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO) throws IdentityException {

        if (StringUtils.isBlank(tenantUUID)) {
            throw new IdentityException("Invalid tenant id: " + tenantId);
        }

        if (serviceProviderDO == null || serviceProviderDO.getIssuer() == null ||
                StringUtils.isBlank(serviceProviderDO.getIssuer())) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        // If an issuer qualifier value is specified, it is appended to the end of the issuer value.
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }
        String issuerId = encodePath(serviceProviderDO.getIssuer());

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            if (processIsServiceProviderExists(connection, issuerId)) {
                if (log.isDebugEnabled()) {
                    if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                        log.debug("SAML2 Service Provider already exists with the same issuer name "
                                + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier name "
                                + serviceProviderDO.getIssuerQualifier());
                    } else {
                        log.debug("SAML2 Service Provider already exists with the same issuer name "
                                + serviceProviderDO.getIssuer());
                    }
                }
                return false;
            }

            processAddServiceProvider(connection, serviceProviderDO, issuerId);
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " with issuer "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier " +
                            serviceProviderDO.getIssuerQualifier() + " is added successfully.");
                } else {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " is added successfully.");
                }
            }
            return true;
        } catch (SQLException e) {
            String msg;
            if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                msg = "Error while adding SAML2 Service Provider for issuer: " + getIssuerWithoutQualifier
                        (serviceProviderDO.getIssuer()) + " and qualifier name " + serviceProviderDO
                        .getIssuerQualifier();
            } else {
                msg = "Error while adding SAML2 Service Provider for issuer: " + serviceProviderDO.getIssuer();
            }
            log.error(msg, e);
            throw new IdentityException(msg, e);
        }
    }

    @Override
    public SAMLSSOServiceProviderDO[] getServiceProviders() throws IdentityException {

        if (StringUtils.isBlank(tenantUUID)) {
            throw new IdentityException("Invalid tenant id: " + tenantId);
        }

        List<SAMLSSOServiceProviderDO> serviceProvidersList = new ArrayList<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            serviceProvidersList = processGetServiceProviders(connection);
        } catch (SQLException e) {
            log.error("Error reading Service Providers", e);
            throw new IdentityException("Error reading Service Providers", e);
        }
        return serviceProvidersList.toArray(new SAMLSSOServiceProviderDO[0]);
    }

    @Override
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        if (StringUtils.isBlank(tenantUUID)) {
            throw new IdentityException("Invalid tenant id: " + tenantId);
        }

        if (issuer == null || StringUtils.isEmpty(issuer.trim())) {
            throw new IllegalArgumentException("Trying to delete issuer \'" + issuer + "\'");
        }

        String issuerId = encodePath(issuer);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            if (!processIsServiceProviderExists(connection, issuerId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Service Provider with issuer " + issuer + " does not exist.");
                }
                return false;
            }

            processDeleteServiceProvider(connection, issuerId);
            return true;
        } catch (SQLException e) {
            String msg = "Error removing the service provider from with name: " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        }
    }

    @Override
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer) throws IdentityException {

        if (StringUtils.isBlank(tenantUUID)) {
            throw new IdentityException("Invalid tenant id: " + tenantId);
        }

        String issuerId = encodePath(issuer);
        SAMLSSOServiceProviderDO serviceProviderDO = null;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            if (isServiceProviderExists(issuer)) {
                serviceProviderDO = processGetServiceProvider(connection, issuerId);
            }
        } catch (SQLException e) {
            throw IdentityException.error(String.format("An error occurred while getting the " +
                    "application certificate id for validating the requests from the issuer '%s'", issuer), e);
        }
        if (serviceProviderDO == null) {
            return null;
        }

        try {
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            // Load the certificate stored in the database, if signature validation is enabled..
            if (serviceProviderDO.isDoValidateSignatureInRequests() ||
                    serviceProviderDO.isDoValidateSignatureInArtifactResolve() ||
                    serviceProviderDO.isDoEnableEncryptedAssertion()) {

                Tenant tenant = IdentityTenantUtil.getTenant(tenantId);
                serviceProviderDO.setX509Certificate(getApplicationCertificate(serviceProviderDO, tenant));
            }
            serviceProviderDO.setTenantDomain(tenantDomain);
        } catch (SQLException | CertificateRetrievingException e) {
            throw IdentityException.error(String.format("An error occurred while getting the " +
                    "application certificate for validating the requests from the issuer '%s'", issuer), e);
        }
        return serviceProviderDO;
    }

    @Override
    public SAMLSSOServiceProviderDO uploadServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {

        throw new NotImplementedException("This operation is not implemented.");

    }

    @Override
    public boolean isServiceProviderExists(String issuer) throws IdentityException {

        if (StringUtils.isBlank(tenantUUID)) {
            throw new IdentityException("Invalid tenant id: " + tenantId);
        }

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            return processIsServiceProviderExists(connection, encodePath(issuer));
        } catch (SQLException e) {
            String msg = "Error while checking existence of Service Provider with issuer: " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        }
    }

    // Private methods

    private boolean processIsServiceProviderExists(Connection connection, String issuerId) throws SQLException {

        boolean isExist = false;

        try (NamedPreparedStatement statement = new NamedPreparedStatement(connection,
                SAMLSSOServiceProviderConstants.SqlQueries.GET_SAML2_SSO_CONFIG_ID_BY_ISSUER)) {
            statement.setString(1, issuerId);
            statement.setString(2, tenantUUID);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    isExist = true;
                }
            }
        }
        return isExist;
    }

    private void processAddServiceProvider(Connection connection, SAMLSSOServiceProviderDO serviceProviderDO,
                                           String issuerId) throws  SQLException {

        try (NamedPreparedStatement statement = new NamedPreparedStatement(connection,
                SAMLSSOServiceProviderConstants.SqlQueries.ADD_SAML2_SSO_CONFIG)) {
            statement.setString(1, issuerId);
            statement.setString(2, tenantUUID);

            statement.setString(3, serviceProviderDO.getIssuer());
            statement.setString(4, listToString(serviceProviderDO.getAssertionConsumerUrlList()));
            statement.setString(5, serviceProviderDO.getDefaultAssertionConsumerUrl());
            statement.setString(6, serviceProviderDO.getCertAlias());
            statement.setString(7, serviceProviderDO.getLoginPageURL());
            statement.setString(8, serviceProviderDO.getNameIDFormat());
            statement.setString(9, serviceProviderDO.getSigningAlgorithmUri());
            statement.setString(10, serviceProviderDO.getDigestAlgorithmUri());
            statement.setString(11, serviceProviderDO.getAssertionEncryptionAlgorithmUri());
            statement.setString(12, serviceProviderDO.getKeyEncryptionAlgorithmUri());

            boolean enableClaimedNameIdClaimedUri = serviceProviderDO.getNameIdClaimUri() != null
                    && serviceProviderDO.getNameIdClaimUri().trim().length() > 0;
            if (enableClaimedNameIdClaimedUri) {
                statement.setString(13, serviceProviderDO.getNameIdClaimUri());
            } else {
                statement.setString(13, null);
            }

            statement.setBoolean(14, serviceProviderDO.isDoSingleLogout());

            if (serviceProviderDO.isDoSingleLogout()) {
                statement.setString(15, getStringIfNotBlank(serviceProviderDO.getSloResponseURL()));
                statement.setString(16, getStringIfNotBlank(serviceProviderDO.getSloRequestURL()));
                // Create doFrontChannelLogout property in the registry.
                statement.setBoolean(17, serviceProviderDO.isDoFrontChannelLogout());
                if (serviceProviderDO.isDoFrontChannelLogout()) {
                    // Create frontChannelLogoutMethod property in the registry.
                    statement.setString(18, serviceProviderDO.getFrontChannelLogoutBinding());
                } else {
                    statement.setString(18, null);
                }
            } else {
                statement.setString(15, null);
                statement.setString(16, null);
                statement.setBoolean(17, false);
                statement.setString(18, null);
            }

            statement.setBoolean(19, serviceProviderDO.isDoSignResponse());
            statement.setBoolean(20, serviceProviderDO.isAssertionQueryRequestProfileEnabled());
            statement.setString(21, serviceProviderDO.getSupportedAssertionQueryRequestTypes());
            statement.setBoolean(22, serviceProviderDO.isEnableSAML2ArtifactBinding());
            statement.setBoolean(23, serviceProviderDO.isDoSignAssertions());
            statement.setBoolean(24, serviceProviderDO.isSamlECP());
            statement.setString(25, listToString(serviceProviderDO.getRequestedClaimsList()));
            statement.setString(26, getStringIfNotBlank(serviceProviderDO.getAttributeConsumingServiceIndex()));
            statement.setString(27, listToString(serviceProviderDO.getRequestedAudiencesList()));
            statement.setString(28, listToString(serviceProviderDO.getRequestedRecipientsList()));
            statement.setBoolean(29, serviceProviderDO.isEnableAttributesByDefault());
            statement.setBoolean(30, serviceProviderDO.isIdPInitSSOEnabled());
            statement.setBoolean(31, serviceProviderDO.isIdPInitSLOEnabled());
            if (serviceProviderDO.isIdPInitSLOEnabled()) {
                statement.setString(32, listToString(serviceProviderDO.getIdpInitSLOReturnToURLList()));
            } else {
                statement.setString(32, null);
            }
            statement.setBoolean(33, serviceProviderDO.isDoEnableEncryptedAssertion());
            statement.setBoolean(34, serviceProviderDO.isDoValidateSignatureInRequests());
            statement.setBoolean(35, serviceProviderDO.isDoValidateSignatureInArtifactResolve());
            statement.setString(36, getStringIfNotBlank(serviceProviderDO.getIssuerQualifier()));
            statement.setString(37, getStringIfNotBlank(serviceProviderDO.getIdpEntityIDAlias()));

            statement.executeUpdate();
        }
    }

    private SAMLSSOServiceProviderDO processGetServiceProvider(Connection connection, String issuer)
            throws SQLException {

        SAMLSSOServiceProviderDO serviceProviderDO = null;
        try (NamedPreparedStatement statement = new NamedPreparedStatement(connection,
                SAMLSSOServiceProviderConstants.SqlQueries.GET_SAML2_SSO_CONFIG_BY_ISSUER)) {
            statement.setString(1, issuer);
            statement.setString(2, tenantUUID);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    serviceProviderDO = resourceToObject(resultSet);
                }
            }
        }
        return serviceProviderDO;
    }

    private List<SAMLSSOServiceProviderDO> processGetServiceProviders(Connection connection) throws SQLException {

        List<SAMLSSOServiceProviderDO> serviceProvidersList = new ArrayList<>();
        try (NamedPreparedStatement statement = new NamedPreparedStatement(connection,
                SAMLSSOServiceProviderConstants.SqlQueries.GET_SAML2_SSO_CONFIGS)) {
            statement.setString(1, tenantUUID);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    SAMLSSOServiceProviderDO serviceProviderDO = resourceToObject(resultSet);
                    serviceProvidersList.add(serviceProviderDO);
                }
            }
        }
        return serviceProvidersList;
    }

    private void processDeleteServiceProvider(Connection connection, String issuerId) throws SQLException {

        try (NamedPreparedStatement statement = new NamedPreparedStatement(connection,
                SAMLSSOServiceProviderConstants.SqlQueries.DELETE_SAML2_SSO_CONFIG_BY_ISSUER)) {
            statement.setString(1, issuerId);
            statement.setString(2, tenantUUID);
            statement.executeUpdate();
        }
    }

    private SAMLSSOServiceProviderDO resourceToObject(ResultSet resultSet) throws  SQLException {

        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();

        serviceProviderDO.setIssuer(resultSet.getString(1));
        serviceProviderDO.setAssertionConsumerUrls(stringToList(resultSet.getString(2)));
        serviceProviderDO.setDefaultAssertionConsumerUrl(resultSet.getString(3));
        serviceProviderDO.setCertAlias(resultSet.getString(4));
        serviceProviderDO.setLoginPageURL(resultSet.getString(5));

        serviceProviderDO.setNameIDFormat(getStringIfNotBlank(resultSet.getString(6)));
        serviceProviderDO.setSigningAlgorithmUri(getStringIfNotBlank(resultSet.getString(7)));
        serviceProviderDO.setDigestAlgorithmUri(getStringIfNotBlank(resultSet.getString(8)));
        serviceProviderDO.setAssertionEncryptionAlgorithmUri(getStringIfNotBlank(resultSet.getString(9)));
        serviceProviderDO.setKeyEncryptionAlgorithmUri(getStringIfNotBlank(resultSet.getString(10)));

        boolean enableClaimedNameIdClaimedUri = resultSet.getString(11) != null
                && resultSet.getString(11).trim().length() > 0;
        if (enableClaimedNameIdClaimedUri) {
            serviceProviderDO.setNameIdClaimUri(resultSet.getString(11));
        }

        serviceProviderDO.setDoSingleLogout(resultSet.getBoolean(12));

        if (serviceProviderDO.isDoSingleLogout()) {
            serviceProviderDO.setSloResponseURL(resultSet.getString(13));
            serviceProviderDO.setSloRequestURL(resultSet.getString(14));
            serviceProviderDO.setDoFrontChannelLogout(resultSet.getBoolean(15));
            // Check front channel logout enable.
            if (serviceProviderDO.isDoFrontChannelLogout()) {
                if (resultSet.getString(16) != null) {
                    serviceProviderDO.setFrontChannelLogoutBinding(resultSet.getString(16));
                } else {
                    // Default is redirect-binding.
                    serviceProviderDO.setFrontChannelLogoutBinding(IdentityRegistryResources
                            .DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING);
                }
            }
        }

        serviceProviderDO.setDoSignResponse(resultSet.getBoolean(17));
        serviceProviderDO.setAssertionQueryRequestProfileEnabled(resultSet.getBoolean(18));
        serviceProviderDO.setSupportedAssertionQueryRequestTypes(getStringIfNotBlank(resultSet.getString(19)));
        serviceProviderDO.setEnableSAML2ArtifactBinding(resultSet.getBoolean(20));
        serviceProviderDO.setDoSignAssertions(resultSet.getBoolean(21));
        serviceProviderDO.setSamlECP(resultSet.getBoolean(22));
        serviceProviderDO.setRequestedClaims(stringToList(resultSet.getString(23)));

        if (resultSet.getString(24) != null) {
            serviceProviderDO.setAttributeConsumingServiceIndex(resultSet.getString(24));
        } else {
            // Specific DB's (like oracle) returns empty strings as null.
            serviceProviderDO.setAttributeConsumingServiceIndex("");
        }

        serviceProviderDO.setRequestedAudiences(stringToList(resultSet.getString(25)));
        serviceProviderDO.setRequestedRecipients(stringToList(resultSet.getString(26)));
        serviceProviderDO.setEnableAttributesByDefault(resultSet.getBoolean(27));
        serviceProviderDO.setIdPInitSSOEnabled(resultSet.getBoolean(28));

        serviceProviderDO.setIdPInitSLOEnabled(resultSet.getBoolean(29));
        if (serviceProviderDO.isIdPInitSLOEnabled()) {
            serviceProviderDO.setIdpInitSLOReturnToURLs(stringToList(resultSet.getString(30)));
        }

        serviceProviderDO.setDoEnableEncryptedAssertion(resultSet.getBoolean(31));
        serviceProviderDO.setDoValidateSignatureInRequests(resultSet.getBoolean(32));
        serviceProviderDO.setDoValidateSignatureInArtifactResolve(resultSet.getBoolean(33));
        serviceProviderDO.setIssuerQualifier(getStringIfNotBlank(resultSet.getString(34)));
        serviceProviderDO.setIdpEntityIDAlias(getStringIfNotBlank(resultSet.getString(35)));

        return serviceProviderDO;
    }

    /**
     * Get the issuer value to be added to registry by appending the qualifier.
     *
     * @param issuer value given as 'issuer' when configuring SAML SP.
     * @return issuer value with qualifier appended.
     */
    private String getIssuerWithQualifier(String issuer, String qualifier) {

        return issuer + IdentityRegistryResources.QUALIFIER_ID + qualifier;
    }

    private String encodePath(String path) {

        String encodedStr = new String(Base64.encodeBase64(path.getBytes()));
        return encodedStr.replace("=", "");
    }

    /**
     * Get the issuer value by removing the qualifier.
     *
     * @param issuerWithQualifier issuer value saved in the registry.
     * @return issuer value given as 'issuer' when configuring SAML SP.
     */
    private String getIssuerWithoutQualifier(String issuerWithQualifier) {

        return StringUtils.substringBeforeLast(issuerWithQualifier, IdentityRegistryResources.QUALIFIER_ID);
    }

    /**
     * Returns the {@link java.security.cert.Certificate} which should used to validate the requests
     * for the given service provider.
     *
     * @param serviceProviderDO
     * @param tenant
     * @return
     * @throws SQLException
     * @throws CertificateRetrievingException
     */
    private X509Certificate getApplicationCertificate(SAMLSSOServiceProviderDO serviceProviderDO, Tenant tenant)
            throws SQLException, CertificateRetrievingException {

        // Check whether there is a certificate stored against the service provider (in the database)
        int applicationCertificateId = getApplicationCertificateId(serviceProviderDO.getIssuer(), tenant.getId());

        CertificateRetriever certificateRetriever;
        String certificateIdentifier;
        if (applicationCertificateId != -1) {
            certificateRetriever = new DatabaseCertificateRetriever();
            certificateIdentifier = Integer.toString(applicationCertificateId);
        } else {
            certificateRetriever = new KeyStoreCertificateRetriever();
            certificateIdentifier = serviceProviderDO.getCertAlias();
        }

        return certificateRetriever.getCertificate(certificateIdentifier, tenant);
    }

    /**
     * Returns the certificate reference ID for the given issuer (Service Provider) if there is one.
     *
     * @param issuer
     * @return
     * @throws SQLException
     */
    private int getApplicationCertificateId(String issuer, int tenantId) throws SQLException {

        try {
            String sqlStmt = isH2DB() ? QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 :
                    QUERY_TO_GET_APPLICATION_CERTIFICATE_ID;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                 PreparedStatement statementToGetApplicationCertificate =
                         connection.prepareStatement(sqlStmt)) {
                statementToGetApplicationCertificate.setString(1, CERTIFICATE_PROPERTY_NAME);
                statementToGetApplicationCertificate.setString(2, issuer);
                statementToGetApplicationCertificate.setInt(3, tenantId);

                try (ResultSet queryResults = statementToGetApplicationCertificate.executeQuery()) {
                    if (queryResults.next()) {
                        return queryResults.getInt(1);
                    }
                }
            }
            return -1;
        } catch (DataAccessException e) {
            String errorMsg = "Error while retrieving application certificate data for issuer: " + issuer +
                    " and tenant Id: " + tenantId;
            throw new SQLException(errorMsg, e);
        }
    }

    /**
     * Get tenant UUID for the given tenant domain.
     *
     * @param tenantId Tenant ID.
     * @return Tenant UUID.
     */
    private String getTenantUUID(int tenantId) {
        // Super tenant does not have a tenant UUID. Therefore, set a hard coded value.
        if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
            // Set a hard length of 32 characters for super tenant ID.
            // This is to avoid the database column length constraint violation.
            return String.format("%1$-32d", tenantId);
        }
        if (tenantId != MultitenantConstants.INVALID_TENANT_ID) {
            Tenant tenant = IdentityTenantUtil.getTenant(tenantId);
            return tenant.getTenantUniqueID();
        }
        return null;
    }

    private String getStringIfNotBlank(String string) {

        return StringUtils.isNotBlank(string) ? string : null;
    }

    private String listToString(List<String> list) {

        return CollectionUtils.isNotEmpty(list) ? String.join(",", list) : null;
    }

    private List<String> stringToList(String string) {

        return StringUtils.isNotBlank(string) ? Arrays.asList(string.split(",")) : null;
    }
}
