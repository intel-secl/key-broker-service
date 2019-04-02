/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.kms.saml.jaxrs.SamlCertificateRepository;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.tag.model.CertificateCollection;
import com.intel.mtwilson.tag.model.CertificateFilterCriteria;
import java.io.IOException;
import java.security.KeyStoreException;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class SamlCertificateRepositoryTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificateRepositoryTest.class);

    @Test
    public void testSearchRepository() throws IOException, KeyStoreException {
        SamlCertificateRepository repository = new SamlCertificateRepository();
        CertificateFilterCriteria criteria = new CertificateFilterCriteria();
        CertificateCollection result = repository.search(criteria);
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        log.debug("search results: {}", mapper.writeValueAsString(result));
    }
}
