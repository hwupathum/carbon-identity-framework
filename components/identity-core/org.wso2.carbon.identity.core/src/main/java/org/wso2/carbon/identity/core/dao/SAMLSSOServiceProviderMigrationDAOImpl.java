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

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;

public class SAMLSSOServiceProviderMigrationDAOImpl implements SAMLSSOServiceProviderDAO {

    private final int tenantId;

    public SAMLSSOServiceProviderMigrationDAOImpl(int tenantId) {
        this.tenantId = tenantId;
    }

    @Override
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO) throws IdentityException {

        return false;
    }

    @Override
    public SAMLSSOServiceProviderDO[] getServiceProviders() throws IdentityException {

        return new SAMLSSOServiceProviderDO[0];
    }

    @Override
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        return false;
    }

    @Override
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer) throws IdentityException {

        return null;
    }

    @Override
    public SAMLSSOServiceProviderDO uploadServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {

        return null;
    }

    @Override
    public boolean isServiceProviderExists(String issuer) throws IdentityException {

        return false;
    }
}
