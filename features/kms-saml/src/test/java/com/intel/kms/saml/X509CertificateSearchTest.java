/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml;

import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.pipe.Filter;
import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.ws.rs.QueryParam;
import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class X509CertificateSearchTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(X509CertificateSearchTest.class);
    private static X509Certificate cert;
    
    @BeforeClass
    public static void readCertificate() throws IOException, CertificateException {
        cert = X509Util.decodePemCertificate(IOUtils.toString(X509CertificateSearchTest.class.getResourceAsStream("/saml.pem"), Charset.forName("UTF-8")));
    }
    
    @Test
    public void testSubjectSearch() {
        /**
         * x509filtercriteria
         *    add(subject().toLowerCase().contains("bob"));     // that means transformation methods return same builder object so next call can be filter... BUT
         *                                                  // what should filter return?   we cannot do contains("bob").equals("alice") because taht wouldn't make
         *                                                  // make any sense, but contains("bob").startsWith("alice")  might make sense for "alice and bob" or "alice, carl, and bob"
         *                                                  // so that part is up to the caller... 
         *    add(sha1().hex().equals(sha1digestHex))
         */
        
        /**
         * user input: "subjectContains=kms"
         * criteria structure:  String subjectContains; 
         * { attribute: "subject", function: "contains", args: [ "kms" ] }
         * { attribute: "subject", class: "StringFunctions.Contains", args: [ "kms" ] }
         * 
         * Need something that knows how to get "subject" out of X509Certificate
         * Can't assume it's just a bean property... in case of subject it's getSubjectX500Principal().getX500Name().getName() or something like that
         * But for whatever IS  bean property a generic method would be fine
         * So factory is needed to determine which properties get instantiated in what way... 
         * And can't get it RIGHT AWAY because it needs to be a function that is applied to every x509 certificate being searched.
         * so it needs to take x509 cert as input and return the field.
         * Now what happens if we want to repeat this pattern for other classes? would be cumbersome to reinvent "contains", "equals", etc. for 
         * common attribute types string, integer, etc.  So the factory needs to specialize in its class but not repeat things that can be generic.
         * 
         * Maybe just need ONE factory that can take any field for THAT CLASS and create the "getter", 
         * using bean properties as default and maybe annotations & functors second?? can use mixins.
         * 
         * 1. take search criteria as input, take target class as input, and take an optional mix-in class as input (if annotations are needed but target class doesn't have them)
         * 2. for each field in the criteria (flat), look for the way to
         *    get its value from an instance of the target class (no actual
         *    instance at this point, just building up functors):
         *    * first, look for any annotations in mixin class that match that field (mixin always overrides target)
         *    * second, look for any annotations in target class that match that field
         *    * third, look for standard javabean property that matches the field;  NOTE currently it must be a plain field name, in future it might be a dot-separated path into a structure... like jsonpath or xpath
         * 3. instantiate a functor to get the value according to class mentioned by mixin/target annotation, or standard known class for basic datatype
         * 4. instantiate a functor to represent the function like "contains", "equals", etc. BUT it MUST BE APPROPRIATE FOR THE VALUE'S TYPE so there could be mutliple functors for "equals" and must choose the right one...
         *    the easiest way to do that is by having a class like "IntegerFunctions" where , once the type is identified as an integer, the available functions are selected from that set...
         *    can use reflection here, to look for 1) available functions, 2) required arguments (just number of args... match to provided args in order, throw exception if count mismatch)
         *    or the annotation can specify the 
         * SECOND REVISION:
         * 1. take search criteria as input
         * 2. search criteria can be a tree... need to walk it and look for fields
         * 
         */
        
    }
    
    public static abstract class MixIn<T> {
        private T instance;
        public void setInstance(T instance) { this.instance = instance; }
        public T getInstance() {
            return instance;
        }
    }
    
    /** use this annotation on the criteria and/or target class or mixin method/field to indicate what is the attribute name that should be matched to this (instead of javabean convention) ... are we talking in the search terms???  **/
    @Target({ElementType.FIELD, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface Attribute {
        String value();
    }

    /** use this annotation on the criteria class to indicate which predicate should be used for a specific field... for example "subjectContains" maps to @Attribute("subject") and @Predicate("contains") .... if only @Attribute is present, how do we guess predicate? match after attribute? if only @Predicaet is present, how do we match attribute?  if none are present, how to match?  can also look fro jax-rs  @QueryParam, @FormParam, etc. but these really don't give much more info... we need to know ATTRIBUTE NAME and WHAT PREDICATE TO APPLY W/ THE ARG... **/
    @Target({ElementType.FIELD, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface Predicate {
        String value();
    }
    
    
    /** use this annotation on the target class or mixin method/field to indicate which predicate factory must be used for quering with this attribute (can be used to restrict functions or introduce custom new ones)... without this, default is to use a known/built-in predicate factory according to the class/type of the value.... maybe allow more than one and use all of them (assume value-type compatible and not overlapping)  **/
    @Target({ElementType.FIELD, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface PredicateFactory {
        Class value();
    }
    
    /** use this annotation on the target class or mixin method/field to indicate where to get the value (relative to the instance being checked)... can be used to make a one-liner annotation to replace a lot of boilerplate "digging into" specific well known place in object **/
    @Target({ElementType.FIELD, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface ValueJXPath {
        String value();
    }
    
    
    public static abstract class X509CertificateSearchMixin extends MixIn<X509Certificate> {
        @ValueJXPath("issuerX500Principal/name")
        public abstract String getIssuerName();
        
        @Attribute("subjectName")
        public String getSubject() {
            return getInstance().getSubjectX500Principal().getName();
        }
        public List<String> getSubjectAlternativeName() {
            byte[] extensionDerEncoded = getInstance().getExtensionValue("2.5.29.17");
            // need to parse it ...
            ArrayList<String> san = new ArrayList<>();
            return san;
        }
    }
    
    /** looks like all our other v2 criteria objects ... this is kept generic so repositories can do whatever they need to with it **/
    /** essentially... this bean becomes a map of arguments to provide... so maybe instead of annotating THIS with a bunch of 
     * attribute/predicate stuff,  we could just build a hard-coded map that has these javabean properties as keys, and the
     * appropriate value-getters and predicates/filters as values, so whatever of these values are filled in will bring in the
     * mapped expressions and supply the filled in value as the argument.....  OR, reuse the QueryParam annotation from jaxrs on
     * the other object... 
     * so THIS ONE:
     */
    public static class X509CertificateQuery {
        @QueryParam("subjectContains")
        public String subjectContains;
        @QueryParam("notBefore")
        public Date notBefore;
        @QueryParam("notAfter")
        public Date notAfter;
        @QueryParam("version")
        public Integer version;
    }
    // corresponds to THIS ONE:
    public static class X509CertificateFilterFactory {
        @QueryParam("subjectContains")
        public Filter<X509Certificate> getSubjectContains(String subjectContainsValue) {
            return null; // new stringfunctions.contains w/ subject from X509CertificateSearchMixin and query value as argument. 
        }
    }
    // or SUPER SIMPLE, 
    public static class X509CertificateFilterCriteria implements Filter<X509Certificate> {
        @QueryParam("subjectContains")
        public String subjectContains;
        @QueryParam("notBefore")
        public Date notBefore;
        @QueryParam("notAfter")
        public Date notAfter;
        @QueryParam("version")
        public Integer version;

        @Override
        public boolean accept(X509Certificate item) {
            boolean match = true;
            // lots of boilerplate... but very readable too.
            if( subjectContains != null && !item.getSubjectX500Principal().getName().contains(subjectContains) ) { match = false; }
            if( notBefore != null && item.getNotBefore().before(notBefore) ) { match = false; }
            return match;
        }
    }
    
    
    
    /** alternative, can be more expressive with less repetition if api accepts json queries instead of url queries.... probably the v2 criteria object can be transformed to this w/ the anntoations then we can just process this **/
    public static class Query {
        public String attribute; // subject, issuer, version, notBefore, notAfter, subjectAlternativeNames, ...
        public String predicate; // equals, contains, before, after, ...
        public String argument;  // "alice", "bob", 2015-01-01, "127.0.0.1", ...
    }
    // ok so it's just like RDF... attribute=subject, predicate=relation, argument=object
    // what about "any", "all", "one", "and", "or", "not" ? 
    
    /** can generate a Filter instance given the filter criteria object , annotations on it, optional mixin with annotations **/
    /** a repository can choose to process filter criteria fields individually or use this filter factory to 
        build a filter automatically for filtering in-memory databases;  a relational-database repository could choose to use
        a different filter that generates SQL clauses instead.
     */
    public static class FilterFactory {
        
        public <T> Filter<T> createFilter(Object criteria, Class<T> targetClass, MixIn<T> mixin) {
        /*
         * 1. take search criteria as input, take target class as input, and take an optional mix-in class as input (if annotations are needed but target class doesn't have them)
         * 2. for each field in the criteria (flat), look for the way to
         *    get its value from an instance of the target class (no actual
         *    instance at this point, just building up functors):
         *    * first, look for any annotations in mixin class that match that field (mixin always overrides target)
         *    * second, look for any annotations in target class that match that field
         *    * third, look for standard javabean property that matches the field;  NOTE currently it must be a plain field name, in future it might be a dot-separated path into a structure... like jsonpath or xpath
         *    * NOTE above applies if criteria is a javabean... if it's a map just use the keys as attribute names.
         * 3. instantiate a functor to get the value according to class mentioned by mixin/target annotation, or standard known class for basic datatype
         * 4. instantiate a functor to represent the function like "contains", "equals", etc. BUT it MUST BE APPROPRIATE FOR THE VALUE'S TYPE so there could be mutliple functors for "equals" and must choose the right one...
         *    the easiest way to do that is by having a class like "IntegerFunctions" where , once the type is identified as an integer, the available functions are selected from that set...
         *    can use reflection here, to look for 1) available functions, 2) required arguments (just number of args... match to provided args in order, throw exception if count mismatch)
         *    or the annotation can specify the 
         */
            return null;
        }
    }
}
