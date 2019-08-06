/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.tpm.identity.jaxrs;

import com.intel.mtwilson.util.filters.StringFunctions;
import com.intel.mtwilson.util.filters.DateFunctions;
import com.intel.mtwilson.util.filters.ByteArrayFunctions;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.ExistingFileResource;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.jaxrs2.server.resource.DocumentRepository;
import com.intel.mtwilson.pipe.Filter;
import com.intel.mtwilson.pipe.FilterPipe;
import com.intel.mtwilson.repository.RepositoryCreateConflictException;
import com.intel.mtwilson.repository.RepositoryCreateException;
import com.intel.mtwilson.repository.RepositoryDeleteException;
import com.intel.mtwilson.repository.RepositoryException;
import com.intel.mtwilson.repository.RepositoryRetrieveException;
import com.intel.mtwilson.repository.RepositorySearchException;
import com.intel.mtwilson.tag.model.Certificate;
import com.intel.mtwilson.tag.model.CertificateCollection;
import com.intel.mtwilson.tag.model.CertificateFilterCriteria;
import com.intel.mtwilson.tag.model.CertificateLocator;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.jxpath.JXPathContext;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author ssbangal
 */
public class TpmIdentityCertificateRepository implements DocumentRepository<Certificate, CertificateCollection, CertificateFilterCriteria, CertificateLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmIdentityCertificateRepository.class);
//    private Configuration configuration;
    private File keystoreFile;
    private String keystoreType;
    private Password keystorePassword = null;

    public TpmIdentityCertificateRepository() throws IOException {
        configure(ConfigurationFactory.getConfiguration());
    }

    public TpmIdentityCertificateRepository(Configuration configuration) {
        configure(configuration);
    }

    private void configure(Configuration configuration) {
        // locate the keystore file that has the trusted tpm identity (privacy ca) certificate authorities
        this.keystoreFile = new File(configuration.get(com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.TPM_IDENTITY_CERTIFICATES_FILE_PROPERTY, Folders.configuration() + File.separator + "tpm.identity.jks"));
        this.keystoreType = configuration.get(com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY, com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE);
        // get the password for the tpm identity (privacy ca) keystore from the password vault
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD)) {
                this.keystorePassword = passwordVault.get(com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD); // throws exception if password is not in vault
            } else {
                //faults.add(new PasswordVaultEntryNotFound(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD));
                log.error("Password vault entry not found: {}", com.intel.kms.tpm.identity.setup.TpmIdentityCertificates.MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD);
                throw new IllegalStateException("Password vault entry not found");
            }
        } catch (IOException | KeyStoreException e) {
            log.error("Cannot obtain keystore password", e);
//            faults.add(new PasswordVaultUnavailable(e));
            throw new IllegalStateException("Password vault not available");
        }
    }

    /*
    private File getTpmIdentityCertificatesFile() {
        return keystoreFile;
    }
    */

    public static class JXPathQuery<T> implements Filter<X509Certificate> {

        private String jxpath;
        private Filter<T> predicate;

        public JXPathQuery(String jxpath, Filter<T> predicate) {
            this.jxpath = jxpath;
            this.predicate = predicate;
        }

        @Override
        public boolean accept(X509Certificate item) {
            T value = (T) JXPathContext.newContext(item).getValue(jxpath);
            return predicate.accept(value);
        }
    }

    public static interface CertificateAttribute<T> {

        T getValue(X509Certificate certificate);
    }

    public static class ValueQuery<T> implements Filter<X509Certificate> {

        private Filter<T> predicate;
        private CertificateAttribute<T> value;

        public ValueQuery(CertificateAttribute<T> value, Filter<T> predicate) {
            this.value = value;
            this.predicate = predicate;
        }

        @Override
        public boolean accept(X509Certificate item) {
            return predicate.accept(value.getValue(item));
        }
    }

    public static class EncodedValue implements CertificateAttribute<byte[]> {

        @Override
        public byte[] getValue(X509Certificate certificate) {
            try {
                return certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Invalid certificate", e);
            }
        }
    }
    
    public List<X509Certificate> getCertificates() throws KeyStoreException, IOException {
        try (PublicKeyX509CertificateStore keystore = new PublicKeyX509CertificateStore(keystoreType, new ExistingFileResource(keystoreFile), keystorePassword)) {
            ArrayList<X509Certificate> list = new ArrayList<>();
            for(String alias : keystore.aliases()) {
                list.add(keystore.get(alias));
            }
            return list;
        }
    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:search")
    public CertificateCollection search(CertificateFilterCriteria criteria) {
        log.debug("TpmIdentityCertificateRepository search");
        CertificateCollection objCollection = new CertificateCollection();

        if (!keystoreFile.exists()) {
            // there are no certificates at all, so return the empty list
            return objCollection;
        }

        try (PublicKeyX509CertificateStore keystore = new PublicKeyX509CertificateStore(keystoreType, new ExistingFileResource(keystoreFile), keystorePassword)) {
            ArrayList<Filter<X509Certificate>> filters = new ArrayList<>();
            if (criteria.filter) {
//                if( criteria.id != null ) {
//                    filters.add(new JXPathQuery("id",new StringFunctions.EqualsIgnoreCase(criteria.id.toString())));                    
//                    sql.addConditions(MW_TAG_CERTIFICATE.ID.equalIgnoreCase(criteria.id.toString())); // when uuid is stored in database as the standard UUID string format (36 chars)
//                }
                if (criteria.subjectEqualTo != null && criteria.subjectEqualTo.length() > 0) {
                    filters.add(new JXPathQuery("subjectX500Principal/name", new StringFunctions.EqualsIgnoreCase(criteria.subjectEqualTo)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.SUBJECT.equalIgnoreCase(criteria.subjectEqualTo));
                }
                if (criteria.subjectContains != null && criteria.subjectContains.length() > 0) {
                    filters.add(new JXPathQuery("subjectX500Principal/name", new StringFunctions.Contains(criteria.subjectContains)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.SUBJECT.lower().contains(criteria.subjectContains.toLowerCase()));
                }
                if (criteria.issuerEqualTo != null && criteria.issuerEqualTo.length() > 0) {
                    filters.add(new JXPathQuery("issuerX500Principal/name", new StringFunctions.EqualsIgnoreCase(criteria.issuerEqualTo)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.ISSUER.equalIgnoreCase(criteria.issuerEqualTo));
                }
                if (criteria.issuerContains != null && criteria.issuerContains.length() > 0) {
                    filters.add(new JXPathQuery("issuerX500Principal/name", new StringFunctions.Contains(criteria.issuerContains.toLowerCase())));
//                    sql.addConditions(MW_TAG_CERTIFICATE.ISSUER.lower().contains(criteria.issuerContains.toLowerCase()));
                }
                if (criteria.sha1 != null) {
                    filters.add(new ValueQuery(new EncodedValue(), new ByteArrayFunctions.Sha1EqualsHex(criteria.sha1.toHexString())));
//                    sql.addConditions(MW_TAG_CERTIFICATE.SHA1.equalIgnoreCase(criteria.sha1.toHexString()));
                }
                if (criteria.sha256 != null) {
                    filters.add(new ValueQuery(new EncodedValue(), new ByteArrayFunctions.Sha256EqualsHex(criteria.sha256.toHexString())));
//                    sql.addConditions(MW_TAG_CERTIFICATE.SHA256.equalIgnoreCase(criteria.sha256.toHexString()));
                }
                if (criteria.sha384 != null) {
                    filters.add(new ValueQuery(new EncodedValue(), new ByteArrayFunctions.Sha384EqualsHex(criteria.sha384.toHexString())));
                }
                if (criteria.validOn != null) {
                    filters.add(new JXPathQuery("notBefore", new DateFunctions.NotAfter(criteria.validOn)));   // the certificate's notBefore date must be ON or EARLIER than the validOn date... that's equivalent to NOT AFTER the validOn date                  
                    filters.add(new JXPathQuery("notAfter", new DateFunctions.NotBefore(criteria.validOn)));   // the certificate's notAfter date must be ON or LATER than the validOn date... that's equivalent to NOT BEFORE the validOn date                 
//                    sql.addConditions(MW_TAG_CERTIFICATE.NOTBEFORE.lessOrEqual(new Timestamp(criteria.validOn.getTime())));
//                    sql.addConditions(MW_TAG_CERTIFICATE.NOTAFTER.greaterOrEqual(new Timestamp(criteria.validOn.getTime())));
                }
                if (criteria.validBefore != null) {
                    filters.add(new JXPathQuery("notAfter", new DateFunctions.NotBefore(criteria.validBefore)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.NOTAFTER.greaterOrEqual(new Timestamp(criteria.validBefore.getTime())));
                }
                if (criteria.validAfter != null) {
                    filters.add(new JXPathQuery("notBefore", new DateFunctions.NotAfter(criteria.validAfter)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.NOTBEFORE.lessOrEqual(new Timestamp(criteria.validAfter.getTime())));
                }
//                if( criteria.revoked != null   ) {
//                    filters.add(new JXPathQuery("revoked",new BooleanFunctions.Equals(criteria.revoked)));
//                    sql.addConditions(MW_TAG_CERTIFICATE.REVOKED.equal(criteria.revoked));
//                }
            }

//            sql.addOrderBy(MW_TAG_CERTIFICATE.SUBJECT);
//            Result<Record> result = sql.fetch();
            ArrayList<Certificate> results = new ArrayList<>();
            FilterPipe<X509Certificate> filterAll = new FilterPipe<>(filters);
            log.debug("Searching keystore with {} filters", filters.size());
            for (String alias : keystore.aliases()) {
                log.debug("Searching keystore, evaluating certificate for alias {}", alias);
                X509Certificate item = keystore.get(alias);
                if (filterAll.accept(item)) {
                    log.debug("Searching keystore, accepted certificate for alias {}", alias);
                    try {
                        Certificate document = toDocument(item);
                        document.setId(UUID.valueOf(alias)); // alias is uuid in hyphen format
                        results.add(document);
                    } catch (CertificateEncodingException e) {
                        log.error("Cannot add certificate to result set", e);
                    }
                }
            }
            objCollection.getCertificates().addAll(results);
        } catch (Exception ex) {
            log.error("Certificate:Search - Error during certificate search.", ex);
            throw new RepositorySearchException(ex, criteria);
        }
        log.debug("Certificate:Search - Returning back {} of results.", objCollection.getCertificates().size());
        return objCollection;
    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:retrieve")
    public Certificate retrieve(CertificateLocator locator) {
        log.debug("TpmIdentityCertificateRepository retrieve");
        if (locator == null || locator.id == null) {
            return null;
        }
        log.debug("Certificate:Retrieve - Got request to retrieve user with id {}.", locator.id);
        try (PublicKeyX509CertificateStore keystore = new PublicKeyX509CertificateStore(keystoreType, new ExistingFileResource(keystoreFile), keystorePassword)) {
            String alias = locator.id.toString(); // uuid in hyphen format
            if (keystore.contains(alias)) {
                X509Certificate item = keystore.get(alias);
                return toDocument(item);
            }
        } catch (Exception ex) {
            log.error("Certificate:Retrieve - Error during certificate retrieval.", ex);
            throw new RepositoryRetrieveException(ex, locator);
        }
        return null;
    }

    public Certificate toDocument(X509Certificate certificate) throws CertificateEncodingException {
        Certificate document = new Certificate();
        byte[] encoded = certificate.getEncoded();
        document.setCertificate(encoded);//.getValue(MW_TAG_CERTIFICATE.CERTIFICATE));  // unlike other table queries, here we can get all the info from the certificate itself... except for the revoked flag
        document.setIssuer(certificate.getIssuerX500Principal().getName()); //.getValue(MW_TAG_CERTIFICATE.ISSUER));
        document.setSubject(certificate.getSubjectX500Principal().getName()); //r.getValue(MW_TAG_CERTIFICATE.SUBJECT));
        document.setNotBefore(certificate.getNotBefore()); //r.getValue(MW_TAG_CERTIFICATE.NOTBEFORE));
        document.setNotAfter(certificate.getNotAfter()); //r.getValue(MW_TAG_CERTIFICATE.NOTAFTER));
        document.setSha1(Sha1Digest.digestOf(encoded));
        document.setSha256(Sha256Digest.valueOf(encoded));
        return document;
    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:store")
    public void store(Certificate item) {
        log.debug("TpmIdentityCertificateRepository store");
        throw new UnsupportedOperationException();

    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:create")
    public void create(Certificate item) {
        log.debug("TpmIdentityCertificateRepository create");
        CertificateLocator locator = new CertificateLocator();
        locator.id = item.getId();
        String alias = locator.id.toString();
//        try (CertificateDAO dao = TagJdbi.certificateDao()) {
        try (PublicKeyX509CertificateStore keystore = new PublicKeyX509CertificateStore(keystoreType, new FileResource(keystoreFile), keystorePassword)) {
            if (keystore.contains(alias)) {
                throw new RepositoryCreateConflictException(locator);
            }

            keystore.set(item.getId().toString(), item.getX509Certificate());
            log.debug("Certificate:Create - Created the Certificate {} successfully.", item.getId().toString());
        } catch (RepositoryException re) {
            throw re;
        } catch (Exception ex) {
            log.error("Certificate:Create - Error during certificate creation.", ex);
            throw new RepositoryCreateException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:delete")
    public void delete(CertificateLocator locator) {
        log.debug("TpmIdentityCertificateRepository delete with locator");
        if (locator == null || locator.id == null) {
            return;
        }
        String alias = locator.id.toString();
        log.debug("Certificate:Delete - Got request to delete Certificate with id {}.", locator.id.toString());
        try (PublicKeyX509CertificateStore keystore = new PublicKeyX509CertificateStore(keystoreType, new ExistingFileResource(keystoreFile), keystorePassword)) {
            if (keystore.contains(alias)) {
                keystore.remove(alias);
            } else {
                log.info("Certificate:Delete - Certificate does not exist in the system.");
            }
        } catch (Exception ex) {
            log.error("Certificate:Delete - Error during certificate deletion.", ex);
            throw new RepositoryDeleteException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("tpm_identity_certificates:delete,search")
    public void delete(CertificateFilterCriteria criteria) {
        log.debug("TpmIdentityCertificateRepository delete with criteria");
        log.debug("Certificate:Delete - Got request to delete certificate by search criteria.");
        CertificateCollection objCollection = search(criteria);
        try {
            for (Certificate obj : objCollection.getCertificates()) {
                CertificateLocator locator = new CertificateLocator();
                locator.id = obj.getId();
                delete(locator);
            }
        } catch (RepositoryException re) {
            throw re;
        } catch (Exception ex) {
            log.error("Certificate:Delete - Error during Certificate deletion.", ex);
            throw new RepositoryDeleteException(ex);
        }
    }
}
