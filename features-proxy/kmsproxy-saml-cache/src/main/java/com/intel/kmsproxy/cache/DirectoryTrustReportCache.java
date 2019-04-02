/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy.cache;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kmsproxy.SecurityAssertionCache;
import com.intel.kmsproxy.SecurityAssertionProvider;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author jbuhacoff
 */
public class DirectoryTrustReportCache implements SecurityAssertionProvider, SecurityAssertionCache {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DirectoryTrustReportCache.class);
    private static final Charset UTF8 = Charset.forName("UTF-8");
    public static final String FEATURE_ID = "trust-report-cache";
    public static final String CACHE_EXPIRES_AFTER_PROPERTY = "trust.report.cache.expires.after";
    private long expiresAfterMillis;
    
    public DirectoryTrustReportCache() throws IOException {
        this(ConfigurationFactory.getConfiguration());
    }
    public DirectoryTrustReportCache(Configuration configuration) {
        File cacheDirectory = new File(Folders.repository(FEATURE_ID));
        if( !cacheDirectory.exists() && !cacheDirectory.mkdirs() ) {
            throw new IllegalStateException("No data directory available");
        }
        long expireAfterSeconds = Long.valueOf(configuration.get(CACHE_EXPIRES_AFTER_PROPERTY, "0")); // by default entries expire immediately, meaning the cache isn't used
        expiresAfterMillis = expireAfterSeconds * 1000L;
    }
    
    private File getFile(String subject) {
        return new File(Folders.repository(FEATURE_ID)+File.separator+subject);
    }

    /**
     * 
     * @param subject
     * @param assertion saml to store in cache;  or NULL to delete any cached assertion for this subject
     * @throws IOException 
     */
    @Override
    public void storeAssertion(String subject, String assertion) throws IOException {
        File reportFile = getFile(subject);
        if( assertion == null ) {
            FileUtils.deleteQuietly(reportFile);
        }
        else {
            FileUtils.writeStringToFile(reportFile, assertion, UTF8);
        }
    }

    /**
     * 
     * @param subject
     * @return the SAML assertion if found and not expired according to file timestamp, or null if not found
     * @throws IOException only on a read error; does NOT throw FileNotFoundException
     */
    @Override
    public String getAssertionForSubject(String subject) throws IOException {
        File reportFile = getFile(subject);
        if( !reportFile.exists() ) { log.debug("No report for {}", subject); return null; }
        long lastModified = reportFile.lastModified();
        long currentTime = System.currentTimeMillis();
        if( lastModified + expiresAfterMillis <= currentTime ) {
            log.debug("Report for {} expired {} seconds ago", subject, (currentTime-lastModified)/1000);
            return null;
        }
        return FileUtils.readFileToString(reportFile, UTF8);
    }
    
}
