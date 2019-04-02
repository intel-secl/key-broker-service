/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.util.filters;

import com.intel.mtwilson.pipe.Filter;
import com.intel.mtwilson.pipe.FilterPipe;
import com.intel.mtwilson.pipe.Transformer;
import com.intel.mtwilson.pipe.TransformerPipe;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * The pattern is that for every field in the certificate object there is
 * a static function which returns a new attribute filter instance for that
 * field. 
 * 
 * An attribute filter accepts an X509Certificate and knows how
 * to extract its attribute from it for comparison; for example the
 * VersionFilter knows to call cert.getVersion(), and the SubjectFilter knows
 * to call cert.getSubjectX500Principal.getName(). 
 * 
 * Because some attributes have similar types, common functionality is
 * grouped into a superclass. For example notBefore and notAfter
 * are both dates, so both derive from a DateFilter class; while subject and 
 * issuer are both X500Principal names, both derive from a StringFilter class.
 * The DateFilter and StringFilter superclasses provide convenience functions
 * to create specific predicates like LessThan, Equals, etc. for the 
 * attribute.
 * 
 * @author jbuhacoff
 */
public class X509CertificateFilters {

    public static SubjectAttributeFilter subject() { return new SubjectAttributeFilter(); }
    public static IssuerAttributeFilter issuer() { return new IssuerAttributeFilter(); }
    public static NotBeforeFilter notBefore() { return new NotBeforeFilter(); }
    public static NotAfterFilter notAfter() { return new NotAfterFilter(); }
    public static VersionFilter version() { return new VersionFilter(); }
    
//    public static DigestFilter md5() { return new DigestFilter(new ByteArrayFunctions.Md5()); }
//    public static DigestFilter sha1() { return new DigestFilter(new ByteArrayFunctions.Sha1()); }
//    public static DigestFilter sha256() { return new DigestFilter(new ByteArrayFunctions.Sha256()); }

    
    public static abstract class AbstractAttributeFilter<T> implements Filter<X509Certificate> {
        private TransformerPipe<T> transformers = new TransformerPipe<>(new ArrayList<Transformer<T>>());
        private FilterPipe<T> filters = new FilterPipe<>(new ArrayList<Filter<T>>());
        
        /**
         * Extracts a single attribute from the X509Certificate, for example
         * the subject, issuer, public key, or the entire encoded certificate.
         * @param item
         * @return 
         */
        public abstract T attribute(X509Certificate item);
        
        public List<Transformer<T>> transformers() { return transformers.getTransformers(); }
        public List<Filter<T>> filters() { return filters.getFilters(); }
        
        @Override
        public boolean accept(X509Certificate item) {
            T attribute = attribute(item);
            T transformed = transformers.transform(attribute); // could be no transformations at all (identity)
            return filters.accept(transformed);
        }
        
    }
    
    public static abstract class Attribute<T> {
        public abstract T getAttribute(X509Certificate certificate);
    }
    
    public static interface Value<T> {
        T getValue();
    }
    
    public static class SubjectAttributeValue implements Value<String> {
        private X509Certificate certificate;
        public SubjectAttributeValue(X509Certificate certificate) {
            this.certificate = certificate;
        }
        @Override
        public String getValue() {
            return certificate.getSubjectX500Principal().getName();
        }
        
    }
    
    public static class SubjectAttributeFilter extends AbstractAttributeFilter<String> {
        @Override
        public String attribute(X509Certificate item) {
            return item.getSubjectX500Principal().getName();
        }

    }

    public static class IssuerAttributeFilter extends AbstractAttributeFilter<String> {
        @Override
        public String attribute(X509Certificate item) {
            return item.getIssuerX500Principal().getName();
        }

    }

    public abstract static class DateFilter extends AbstractAttributeFilter<Date> {

        public DateFilter equals(Date equalDate) {
            filters().add(new DateFunctions.Equals(equalDate));
            return this;
        }
        public DateFilter before(Date beforeDate) {
            filters().add(new DateFunctions.Before(beforeDate));
            return this;
        }
        public DateFilter after(Date afterDate) {
            filters().add(new DateFunctions.After(afterDate));
            return this;
        }
        public DateFilter notBefore(Date notBeforeDate) {
            filters().add(new DateFunctions.NotBefore(notBeforeDate));
            return this;
        }
        public DateFilter notAfter(Date notAfterDate) {
            filters().add(new DateFunctions.NotAfter(notAfterDate));
            return this;
        }
    }
    
    public static class NotBeforeFilter extends DateFilter {
        @Override
        public Date attribute(X509Certificate item) {
            return item.getNotBefore();
        }

    }
    public static class NotAfterFilter extends DateFilter {
        @Override
        public Date attribute(X509Certificate item) {
            return item.getNotAfter();
        }

    }
    
    public abstract static class IntegerFilter extends AbstractAttributeFilter<Integer> {
        public IntegerFilter equals(Integer equalDate) {
            filters().add(new IntegerFunctions.Equals(equalDate));
            return this;
        }
        public IntegerFilter lessThan(Integer lessThanDate) {
            filters().add(new IntegerFunctions.LessThan(lessThanDate));
            return this;
        }
        public IntegerFilter greaterThan(Integer greaterThanDate) {
            filters().add(new IntegerFunctions.GreaterThan(greaterThanDate));
            return this;
        }
        public IntegerFilter notLessThan(Integer notLessThanDate) {
            filters().add(new IntegerFunctions.NotLessThan(notLessThanDate));
            return this;
        }
        public IntegerFilter notGreaterThan(Integer notGreaterThanDate) {
            filters().add(new IntegerFunctions.NotGreaterThan(notGreaterThanDate));
            return this;
        }
        
    }
    
    public static class VersionFilter extends IntegerFilter {
        @Override
        public Integer attribute(X509Certificate item) {
            return item.getVersion();
        }
    }
    
    public static class DigestFilter extends AbstractAttributeFilter<byte[]> {
        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DigestFilter.class);

        private Transformer<byte[]> digest;

        public DigestFilter(Transformer<byte[]> digest) {
            this.digest = digest;
        }
        
        public DigestFilter equals(byte[] test) {
            filters().add(new ByteArrayFunctions.Equals(test));
            return this;
        }

        public DigestFilter equalsHex(String testHex) {
            try {
            filters().add(new ByteArrayFunctions.Equals(Hex.decodeHex(testHex.toCharArray())));
            return this;
            }
            catch(DecoderException e) {
                log.debug("Invalid hex input to DigestFilter.equalsHex: {}", testHex);
                throw new IllegalArgumentException("Invalid hex string");
            }
        }
        
        @Override
        public byte[] attribute(X509Certificate item) {
            try {
            return digest.transform(item.getEncoded());
            }
            catch(CertificateEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }
        
    }
    
    public abstract static class StringFilter<T> implements Filter<T> {

        private ArrayList<Transformer<String>> transformers = new ArrayList<>();
        private ArrayList<Filter<String>> filters = new ArrayList<>();

        public abstract String getString(T input);

        @Override
        public boolean accept(T item) {
            TransformerPipe<String> tpipe = new TransformerPipe<>(transformers);
            String transformed = tpipe.transform(getString(item)); // could be no transformations at all (identity)
            FilterPipe<String> fpipe = new FilterPipe<>(filters);
            return fpipe.accept(transformed);
        }

        public StringFilter equalsIgnoreCase(String test) {
            filters.add(new StringFunctions.EqualsIgnoreCase(test));
            return this;
        }

        public StringFilter contains(String test) {
            filters.add(new StringFunctions.Contains(test));
            return this;
        }

        public StringFilter toLowerCase() {
            transformers.add(new StringFunctions.LowerCase());
            return this;
        }

        public StringFilter toUpperCase() {
            transformers.add(new StringFunctions.LowerCase());
            return this;
        }

        public StringFilter replaceAll(String regex, String replacement) {
            transformers.add(new StringFunctions.ReplaceAll(regex, replacement));
            return this;
        }

        public StringFilter replaceFirst(String regex, String replacement) {
            transformers.add(new StringFunctions.ReplaceFirst(regex, replacement));
            return this;
        }
        
/*
    public StringTransformerBuilder toLowerCase() {
        list.add(new LowerCase());
        return this;
    }

    
    public StringTransformerBuilder toUpperCase() {
        list.add(new UpperCase());
        return this;
    }
 
    public StringTransformerBuilder replaceAll(String regex, String replacement) {
        list.add(new ReplaceAll(regex, replacement));
        return this;
    }

    
    public StringTransformerBuilder replaceFirst(String regex, String replacement) {
        list.add(new ReplaceFirst(regex, replacement));
        return this;
    } * 
 */        
    }

    public abstract static class X509CertificateStringFilter extends StringFilter<X509Certificate> {
    }


    public abstract static class ByteArrayFilter implements Filter<X509Certificate> {

        private ArrayList<Filter<byte[]>> filters = new ArrayList<>();

        public abstract byte[] getByteArray(X509Certificate input);

        @Override
        public boolean accept(X509Certificate item) {
            FilterPipe<byte[]> fpipe = new FilterPipe<>(filters);
            return fpipe.accept(getByteArray(item));
        }
    }

    /*
     if( criteria.id != null ) {
     sql.addConditions(MW_TAG_CERTIFICATE.ID.equalIgnoreCase(criteria.id.toString())); // when uuid is stored in database as the standard UUID string format (36 chars)
     }
     if( criteria.subjectEqualTo != null  && criteria.subjectEqualTo.length() > 0 ) {
     sql.addConditions(MW_TAG_CERTIFICATE.SUBJECT.equalIgnoreCase(criteria.subjectEqualTo));
     }
     if( criteria.subjectContains != null  && criteria.subjectContains.length() > 0  ) {
     sql.addConditions(MW_TAG_CERTIFICATE.SUBJECT.lower().contains(criteria.subjectContains.toLowerCase()));
     }
     if( criteria.issuerEqualTo != null  && criteria.issuerEqualTo.length() > 0 ) {
     sql.addConditions(MW_TAG_CERTIFICATE.ISSUER.equalIgnoreCase(criteria.issuerEqualTo));
     }
     if( criteria.issuerContains != null  && criteria.issuerContains.length() > 0  ) {
     sql.addConditions(MW_TAG_CERTIFICATE.ISSUER.lower().contains(criteria.issuerContains.toLowerCase()));
     }
     if( criteria.sha1 != null  ) {
     sql.addConditions(MW_TAG_CERTIFICATE.SHA1.equalIgnoreCase(criteria.sha1.toHexString()));
     }
     if( criteria.sha256 != null  ) {
     sql.addConditions(MW_TAG_CERTIFICATE.SHA256.equalIgnoreCase(criteria.sha256.toHexString()));
     }
     if( criteria.validOn != null ) {
     sql.addConditions(MW_TAG_CERTIFICATE.NOTBEFORE.lessOrEqual(new Timestamp(criteria.validOn.getTime())));
     sql.addConditions(MW_TAG_CERTIFICATE.NOTAFTER.greaterOrEqual(new Timestamp(criteria.validOn.getTime())));
     }
     if( criteria.validBefore != null ) {
     sql.addConditions(MW_TAG_CERTIFICATE.NOTAFTER.greaterOrEqual(new Timestamp(criteria.validBefore.getTime())));
     }
     if( criteria.validAfter != null ) {
     sql.addConditions(MW_TAG_CERTIFICATE.NOTBEFORE.lessOrEqual(new Timestamp(criteria.validAfter.getTime())));
     }
     if( criteria.revoked != null   ) {
     sql.addConditions(MW_TAG_CERTIFICATE.REVOKED.equal(criteria.revoked));
     } * 
     */
}
