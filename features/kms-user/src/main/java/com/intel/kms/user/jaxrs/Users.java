/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.user.jaxrs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.ValidationUtil;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.kms.user.UserCollection;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.kms.user.User;
import com.intel.mtwilson.jaxrs2.NoLinks;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.jaxrs2.mediatype.DataMediaType;
import com.intel.mtwilson.jaxrs2.server.resource.AbstractJsonapiResource;
import com.intel.mtwilson.launcher.ws.ext.V2;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BeanParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/users")
public class Users extends AbstractJsonapiResource<User, UserCollection, UserFilterCriteria, NoLinks<User>, UserLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Users.class);
    private UserRepository repository;

    public Users() {
        repository = new UserRepository();
    }

    @Override
    protected UserCollection createEmptyCollection() {
        return new UserCollection();
    }

    @Override
    protected UserRepository getRepository() {
        return repository;
    }

    @PUT
    @Consumes({CryptoMediaType.APPLICATION_X_PEM_FILE})
    @Path("/{id}/transfer-key")
    public void editTransferKey(@BeanParam UserLocator locator, String transferKeyPem, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse) {
        User user = getRepository().retrieve(locator);
        if (user == null) {
            httpServletResponse.setStatus(Status.CONFLICT.getStatusCode());
        } else {
            try {
                if (transferKeyPem.startsWith("-----BEGIN PUBLIC KEY-----")) {
                    PublicKey transferKey = RsaUtil.decodePemPublicKey(transferKeyPem);
                    user.setTransferKey(transferKey);
                } else if (transferKeyPem.startsWith("-----BEGIN CERTIFICATE-----")) {
                    X509Certificate transferKey = X509Util.decodePemCertificate(transferKeyPem);
                    user.setTransferKey(transferKey);
                } else {
                    log.error("Unrecognized transfer key PEM format", transferKeyPem);
                    httpServletResponse.setStatus(Status.BAD_REQUEST.getStatusCode());
                    return;
                }
                getRepository().store(user);
                httpServletResponse.setStatus(Status.NO_CONTENT.getStatusCode());
            } catch (Exception e) {
                log.error("Cannot edit public key", e);
                httpServletResponse.setStatus(Status.BAD_REQUEST.getStatusCode());
            }
        }
    }

    @GET
    @Produces({CryptoMediaType.APPLICATION_X_PEM_FILE})
    @Path("/{id}/transfer-key")
    public String getTransferKey(@BeanParam UserLocator locator, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse) {
        User user = getRepository().retrieve(locator);
        if (user == null) {
            httpServletResponse.setStatus(Status.NOT_FOUND.getStatusCode());
            return null;
        } else {
            return user.getTransferKeyPem();
            /*
             try {
             return user.getTransferKey();
             }
             catch(CryptographyException e) {
             log.error("Cannot retrieve public key", e);
             httpServletResponse.setStatus(Status.INTERNAL_SERVER_ERROR.getStatusCode());
             return null;
             }
             */
        }
    }
}
