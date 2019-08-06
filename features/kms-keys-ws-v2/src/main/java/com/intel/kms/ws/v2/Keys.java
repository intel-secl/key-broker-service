/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.util.PemUtils;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;
import com.intel.mtwilson.jaxrs2.NoLinks;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.jaxrs2.server.resource.AbstractJsonapiResource;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.shiro.ShiroUtil;
import com.intel.mtwilson.util.validation.faults.Thrown;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class Keys extends AbstractJsonapiResource<Key, KeyCollection, KeyFilterCriteria, NoLinks<Key>, KeyLocator> {

    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Keys.class);
    final protected static String AUTHORIZATION_HEADER = "Authorization";
    final private KeyRepository repository;
    final private ObjectMapper mapper;

    public Keys() {
        repository = new KeyRepository();
        mapper = JacksonObjectMapperProvider.createDefaultMapper();
    }

    @Override
    protected KeyCollection createEmptyCollection() {
        return new KeyCollection();
    }

    @Override
    protected KeyRepository getRepository() {
        return repository;
    }

    /**
     * Register an existing key in PEM format.
     *
     * The PEM banner MUST BE BEGIN/END "ENCRYPTED KEY" The PEM headers MUST
     * include "Content-Algorithm", "Encryption-Algorithm", and
     * "Encryption-Key-Id" The "Encryption-Key-Id" MUST be the SHA-256 digest of
     * the recipient public key
     *
     * Example request:
     * <pre>
     * POST /keys
     * Content-Type: application/x-pem-file
     * Accept: application/json
     *
     * -----BEGIN ENCRYPTED KEY-----
     * Content-Algorithm: AES
     * Encryption-Algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * Encryption-Key-Id: 46ba3e67b437aa837744bdb65fc955bcad541219a4809f95a850ab1a9dfb2e17
     *
     * eNxt9yRbo1kKe+Qy2J923AjWTQAuCGDZc8/cC6DrxV6FwoJRX8veBpvOQZGnC22/QbwunKIM4GRY
     * NRGAZlX7q+H5eOspYO8Qn8Uhp1YFkDGDhDPapuHBP1sArxLzCZWFGSCtOKb8TsUPiSTxP7f5ookf
     * ivXFwPeFHg10nyXPk9vNO1pVPCPMjEP+HH3VWhRUWaFzRzdUtYdeofCV4pXbl7+dPpzhg7I5prKL
     * xmlOk4Hyi5sIieZ/feKaTBAKBokaV5LFME4TFofIcyR5JbGiNfbFQaaYpC73gM/hYITL49XDTHha
     * bU/QSf6GlPgb3vcz0Y1eGnNsaXRJNiUMhiF8dA==
     * -----END ENCRYPTED KEY-----
     * </pre>
     *
     * Example response:
     * <pre>
     * {"keys":[{
     * "id":"17bfce7c-6f37-4429-96ec-644b179ba1ce",
     * "algorithm":"AES",
     * "key_length":128,
     * "mode":"OFB",
     * "transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization",
     * "transfer_link":"https://10.1.69.89/v1/keys/17bfce7c-6f37-4429-96ec-644b179ba1ce/transfer"
     * }]}
     * </pre>
     *
     * @param pemText the PEM-formatted encrypted key
     * @return
     */
    @POST
    @Consumes(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyCollection registerKeyPEM(String pemText)  {
        log.debug("registerKeyPEM");
        return getRepository().registerFromPEM(pemText);
    }

    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:transfer")
    public TransferKeyResponse transferKey(@QueryParam("context") String context, @PathParam("keyId") String keyId, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse /*, TransferKeyRequest keyRequest*/)  {
        log.debug("transferKey");
        TransferKeyRequest keyRequest = new TransferKeyRequest();
        keyRequest.setKeyId(keyId);
        if (context != null && !context.isEmpty()) {
            keyRequest.set("context", context);
        }
        keyRequest.set("OAuth2-Authorization", httpServletRequest.getHeader("OAuth2-Authorization"));
        keyRequest.setUsername(ShiroUtil.subjectUsername());
        try {
            return getRepository().getKeyManager().transferKey(keyRequest);
        } catch (Exception e) {
            TransferKeyResponse response = new TransferKeyResponse();
            response.getFaults().add(new Thrown(e));
            response.getHttpResponse().setStatusCode(Response.Status.UNAUTHORIZED.getStatusCode());
            return response;
        }
    }

    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @RequiresPermissions("keys:transfer")
    public String transferKeyPEM(@QueryParam("context") String context, @PathParam("keyId") String keyId, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse /*, TransferKeyRequest keyRequest*/) throws IOException  {
        log.debug("transferKeyPEM");
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest();
        transferKeyRequest.setKeyId(keyId);
        if (context != null && !context.isEmpty()) {
            transferKeyRequest.set("context", context);
        }
        transferKeyRequest.set("OAuth2-Authorization", httpServletRequest.getHeader("OAuth2-Authorization"));
        transferKeyRequest.setUsername(ShiroUtil.subjectUsername());
        TransferKeyResponse transferKeyResponse = getRepository().getKeyManager().transferKey(transferKeyRequest);
        if (transferKeyResponse.getKey() != null) {
            Pem pem = PemUtils.fromTransferKeyResponse(transferKeyResponse.getKey(), transferKeyResponse.getDescriptor());
            if (pem == null) {
                log.error("null pem retrieved from transfer key response.");
            } else {

                log.debug("transfer key pem in string format : \n{}\n", pem.toString());
                return pem.toString();
            }
        }
        return null;
    }

    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @RequiresPermissions("keys:transfer")
    public byte[] transferKeyPEMAsEncryptedBytes(@QueryParam("context") String context, @PathParam("keyId") String keyId, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse /*, TransferKeyRequest keyRequest*/) throws IOException   {
        log.debug("transferKeyPEMAsEncryptedBytes");
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest();
        transferKeyRequest.setKeyId(keyId);
        if (context != null && !context.isEmpty()) {
            log.debug("setting context {}", context);
            transferKeyRequest.set("context", context);
        }
        transferKeyRequest.set("OAuth2-Authorization", httpServletRequest.getHeader("OAuth2-Authorization"));
        TransferKeyResponse transferKeyResponse = getRepository().getKeyManager().transferKey(transferKeyRequest);
//        TransferKeyResponse transferKeyResponse = getRepository().transferKey(transferKeyRequest);
        if (transferKeyResponse.getKey() != null) {
            log.debug("transfer key in binary format");
            return transferKeyResponse.getKey();
        }
        return null;
    }

}