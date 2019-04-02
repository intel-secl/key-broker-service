/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.saml.jaxrs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.ValidationUtil;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.tag.model.Certificate;
import com.intel.mtwilson.tag.model.CertificateCollection;
import com.intel.mtwilson.tag.model.CertificateFilterCriteria;
import com.intel.mtwilson.tag.model.CertificateLocator;
import com.intel.mtwilson.jaxrs2.NoLinks;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.jaxrs2.server.resource.AbstractCertificateJsonapiResource;
import com.intel.mtwilson.launcher.ws.ext.V2;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.ws.rs.BeanParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/saml-certificates")
public class SamlCertificates extends AbstractCertificateJsonapiResource<Certificate, CertificateCollection, CertificateFilterCriteria, NoLinks<Certificate>, CertificateLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);

    private SamlCertificateRepository repository;
    
    public SamlCertificates() {
        try {
            repository = new SamlCertificateRepository();
        }
        catch(Exception e) {
            log.error("SamlCertificateRepository not available", e);
        }
    }
    
    @Override
    protected CertificateCollection createEmptyCollection() {
        return new CertificateCollection();
    }

    @Override
    protected SamlCertificateRepository getRepository() {
        if( repository == null ) { throw new IllegalStateException("Repository not available"); }
        return repository;
    }

    @Override /* from AbstractSimpleResource */
    @GET
    public CertificateCollection searchCollection(@BeanParam CertificateFilterCriteria selector) {
//        try { log.debug("searchCollection: {}", mapper.writeValueAsString(selector)); } catch(JsonProcessingException e) { log.debug("searchCollection: cannot serialize selector: {}", e.getMessage()); }
        try {
            ValidationUtil.validate(selector);
            CertificateCollection collection = getRepository().search(selector);
            List<Certificate> documents = collection.getDocuments();
            for(Certificate document : documents) {
                // the href should really be to the json (no suffix) document... we should use a link for the cert format
                document.getMeta().put("href", String.format("/v1/saml-certificates/%s.crt", document.getId().toString())); // XXX TODO: because we're overriding search method from superclass, we cant get new parameter context httprequest and find our base url... hard-coding /v1 here is not good.
            }
            return collection;
        }
        catch(Exception e) {
            log.error("Search on SAML certificates failed", e);
            CertificateCollection collection = new CertificateCollection();
            collection.getMeta().put("error", "unable to perform the search; check filter criteria");
            return collection;
        }
    }
    

    
    @POST
    @Consumes({CryptoMediaType.APPLICATION_PKIX_CERT})
    @Produces({MediaType.APPLICATION_JSON})
    public Certificate createOneX509CertificateDER(byte[] certificateBytes) {
        try {
            X509Certificate certificate = X509Util.decodeDerCertificate(certificateBytes);
//            ValidationUtil.validate(certificate); // throw new MWException(e, ErrorCode.AS_INPUT_VALIDATION_ERROR, input, method.getName());
            Certificate item = new Certificate();
            item.setId(new UUID());
            item.setCertificate(certificate.getEncoded());
            getRepository().create(item);
            return item;
        }
        catch(CertificateException e) {
            throw new WebApplicationException(Status.BAD_REQUEST); // input error
        }
        
    }

    @POST
    @Consumes({CryptoMediaType.APPLICATION_X_PEM_FILE})
    @Produces({MediaType.APPLICATION_JSON})
    public Certificate createOneX509CertificatePEM(String certificatePem) {
        try {
            X509Certificate certificate = X509Util.decodePemCertificate(certificatePem);
//            ValidationUtil.validate(certificate); // throw new MWException(e, ErrorCode.AS_INPUT_VALIDATION_ERROR, input, method.getName());
            Certificate item = new Certificate();
            item.setId(new UUID());
            item.setCertificate(certificate.getEncoded());
            getRepository().create(item);
            return item;
        }
        catch(CertificateException e) {
            throw new WebApplicationException(Status.BAD_REQUEST); // input error
        }
        
    }
    
}
