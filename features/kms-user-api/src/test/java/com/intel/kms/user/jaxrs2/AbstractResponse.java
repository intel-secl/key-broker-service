/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.dcsg.cpg.validation.Faults;
import com.intel.mtwilson.collection.MultivaluedHashMap;
import com.intel.mtwilson.jaxrs2.Link;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY) // jackson 2.0
public abstract class AbstractResponse implements Faults {
/*
    @JsonUnwrapped
    private final Attributes extensions = new Attributes();
    * */
    /**
     * The httpResponse member does NOT get serialized in responses, it exists
     * so that a "business layer" object can provide hints on the content type
     * and status of the response without preempting other processing or losing
     * other response information by throwing an exception
     */
    private final HttpResponse httpResponse = new HttpResponse();
    /**
     * On success, there could be links to relevant information, such as a
     * rel:created link for created keys, or rel:registered link for registered
     * keys.
     */
    private final List<Link> links = new ArrayList<>();
    /**
     * On failure, there should be one or more faults here detailing what went
     * wrong.
     */
    private final List<Fault> faults = new ArrayList<>();

    public AbstractResponse() {
        super();
    }
/*
    @JsonIgnore
    public Attributes getExtensions() {
        return extensions;
    }
*/
    @JsonIgnore
    public HttpResponse getHttpResponse() {
        return httpResponse;
    }

    public static class HttpResponse {

        private Integer status = null;
        private final MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();

        public Integer getStatusCode() {
            return status;
        }

        public MultivaluedHashMap<String, String> getHeaders() {
            return headers;
        }

        public void setStatusCode(Integer statusCode) {
            this.status = statusCode;
        }
    }

    public List<Link> getLinks() {
        return links;
    }

    @Override
    public List<Fault> getFaults() {
        return faults;
    }
}
