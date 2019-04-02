/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy.jaxrs;

import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kmsproxy.MtWilsonV2Client;
import com.intel.kmsproxy.cache.DirectoryTrustReportCache;
import com.intel.kmsproxy.model.HostInfo;

import com.intel.mtwilson.collection.MultivaluedHashMap;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.launcher.ws.ext.V2;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 *
 * @author rpravee1
 */
@V2
@Path("/keys")
public class ProxyGetKeyWithHardwareUUID {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProxyGetKeyWithHardwareUUID.class);

    /**
     * Example request:
     *
     * <pre>
     * curl --verbose --insecure -X POST
     * -H "Content-Type: text/plain"
     * -H "Accept: application/octet-stream"
     * --data-binary
     *
     * @hardware-uuid
     * http://keyserver/v1/keys/testkey2
     * </pre>
     *
     *
     * The response content type is determined by the client's Accept header and
     * the remote key server's supported options.
     *
     * @param keyId
     * @param hostHardwareUUID
     * @return
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.APPLICATION_JSON)
    public byte[] getKey(@PathParam("keyId") String keyId, HostInfo hostInfo, @Context HttpServletRequest httpRequest, @Context HttpServletResponse httpResponse) {
        log.debug("ProxyGetKeyWithHardwareUUID");
        log.debug("Method: {}", httpRequest.getMethod()); // example:  POST
        log.debug("Scheme: {}", httpRequest.getScheme()); // example:  http
        log.debug("RequestURL: {}", httpRequest.getRequestURL()); // example:  http://10.255.72.191/v1/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("RequestURI: {}", httpRequest.getRequestURI()); // example:  /v1/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("ServerName: {}", httpRequest.getServerName()); // example:  10.255.72.191
        log.debug("ServerPort: {}", httpRequest.getServerPort()); // example:  80
        log.debug("ContextPath: {}", httpRequest.getContextPath()); // example:  (blank)
        log.debug("PathInfo: {}", httpRequest.getPathInfo()); // example:  /keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("PathTranslated: {}", httpRequest.getPathTranslated()); // example:  C:\Users\jbuhacof\workspace\dcg_security-kms\kms-html5\src\main\resources\www\keys\3787f629-1827-411e-866e-ce87e37f805a\transfer
        log.debug("RemoteAddr: {}", httpRequest.getRemoteAddr()); // example:  10.1.71.180
        log.debug("ServletPath: {}", httpRequest.getServletPath()); // example:  /v1
        log.debug("HostInfo: {}", hostInfo.getHardwareUUID());
        try {
                UUID hardwareUUID = com.intel.dcsg.cpg.io.UUID.valueOf(hostInfo.getHardwareUUID());
                ProxyResponse backendResponse = proxyKeyRequestByUUID(keyId, hardwareUUID, httpRequest);
                prepareResponse(httpResponse, backendResponse);
                return backendResponse.content;

        }
        //Removed com.intel.mtwilson.api.ApiException and com.intel.mtwilson.api.ClientException since mtwilson doesnt build mtwilson-api package
        catch (CryptographyException | GeneralSecurityException | IOException e) {
            throw new WebApplicationException("Cannot retrieve key", e);
        }
    }

    private void prepareResponse(HttpServletResponse httpResponse, ProxyResponse backendResponse) {
        // copy all response headers from key server to our response, should include content type
        for (String headerName : backendResponse.headers.keys()) {
            for (String headerValue : backendResponse.headers.get(headerName)) {
                log.debug("Adding response header {}: {}", headerName, headerValue);
                httpResponse.addHeader(headerName, headerValue);
            }
        }
    }

    private static class ProxyResponse {

        byte[] content = null;
        MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();
    }

    //Removed com.intel.mtwilson.api.ApiException and com.intel.mtwilson.api.ClientException since mtwilson doesnt build mtwilson-api package
    private ProxyResponse proxyKeyRequestByUUID(String keyId, UUID hardwareUUID, HttpServletRequest request) throws CryptographyException, GeneralSecurityException, IOException {
        //String aikId = aikPubKeySha256Digest.toHexString();
        log.debug("proxyKeyRequestByUUID for keyId: {}", hardwareUUID);
        DirectoryTrustReportCache trustReportCache = new DirectoryTrustReportCache();

        String saml;

        // first try the local cache
        try {
            log.debug("Checking local cache for aik: {}", hardwareUUID);
            // will return saml if found,  null if not found or expired,  or throw exception only on read error
            saml = trustReportCache.getAssertionForSubject(hardwareUUID.toString());
            if( saml != null ) {
                // we found a report in the cache, and it's not expired according to our setting trust.report.cache.expires.after
                // but we have to also check the expiration date in the report itself
                MtWilsonV2Client client = new MtWilsonV2Client();
                if( !client.isReportValid(saml) ) {
                    log.debug("Invalid report cached for aik: {}", hardwareUUID);
                    trustReportCache.storeAssertion(hardwareUUID.toString(), null);
                    saml = null;
                }
            }
            if( saml == null ) {
                log.debug("No current report cached for aik: {}", hardwareUUID);
            }
        } catch (IOException e) {
            log.error("Error while reading cached report for aik: {}", hardwareUUID, e);
            saml = null;
        }

        // second, try getting the report from attestation service
        if (saml == null) {
            log.debug("Checking attestation service for aik: {}", hardwareUUID);
            MtWilsonV2Client client = new MtWilsonV2Client();
            saml = client.getAssertionForHarwareUUID(hardwareUUID);
            log.debug("Trust report received from attestation service: {}", saml);
            if (saml != null) {
                // store it in cache
                try {
                    trustReportCache.storeAssertion(hardwareUUID.toString(), saml);
                } catch (IOException e) {
                    log.error("Cannot store report in cache for aik: {}", hardwareUUID.toString(), e);
                }
            }
        }

        // if we don't have a report by now, return an error to client - we won't be able to retrieve the key
        if( saml == null ) {
            log.debug("No trust report available for aik: {}", hardwareUUID.toString());
            throw new NotFoundException();
        }

        // 2. post SAML report to original URL, capture result

        // create  http client for request.getRequestURL()  , post the saml content and fwd same accept header provided by client
        log.debug("proxyKeyRequestByAik to key server: {}", request.getRequestURL().toString());
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod(request.getRequestURL().toString());

        log.debug("proxyKeyRequestByAik POST URI: {}", post.getURI().toString());

        // we need to copy AT LEAST the "Accept" header, but since we're a proxy we should copy ALL the headers
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            for (String headerName : Collections.list(headerNames)) {
                log.debug("proxyKeyRequestByAik adding header {}: {}", headerName, request.getHeader(headerName));
                post.addRequestHeader(headerName, request.getHeader(headerName));
//                    post.addRequestHeader("Accept", request.getHeader("Accept"));
            }
        }

        // remove the client's Content-Type and Content-Length headers because
        // we are replacing the message body with the SAML report, and keeping
        // these headers would result in either 415 Unsupported Media Type or
        // truncated message at server (due to incorrect content-length)
        post.removeRequestHeader("Content-Type"); // post.setRequestHeader("Content-Type", CryptoMediaType.APPLICATION_SAML);
        post.removeRequestHeader("Content-Length");

        post.setRequestEntity(new StringRequestEntity(saml, CryptoMediaType.APPLICATION_SAML, "UTF-8"));

        int status = client.executeMethod(post);
        if (status != HttpStatus.SC_OK) {
            log.error("proxyKeyRequestByAik got error response from key server: {} {}", post.getStatusCode(), post.getStatusText());
            // forward the remote error to the client with same code and status text;  currently not forwarding the response body
            throw new WebApplicationException(post.getStatusText(), status);
        }

        ProxyResponse response = new ProxyResponse();
        response.content = post.getResponseBody();

        // copy all response headaers, including content type
        for (Header header : post.getResponseHeaders()) {
            response.headers.add(header.getName(), header.getValue());
            log.debug("proxyKeyRequestByAik got response header {}: {}", header.getName(), header.getValue());
        }

//        response.contentType = post.getResponseHeader("Content-Type").getValue();

        post.releaseConnection();

        // 3. return result to client as-is
        return response;
    }
}
