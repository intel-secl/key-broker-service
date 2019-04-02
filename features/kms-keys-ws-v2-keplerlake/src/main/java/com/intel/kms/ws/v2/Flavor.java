/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author kchinnax
 */
public class Flavor {

    @JsonProperty("label")
    private String label;

    @JsonProperty("uri")
    private String uri;

    @JsonProperty("etag")
    private String etag;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getEtag() {
        return etag;
    }

    public void setEtag(String etag) {
        this.etag = etag;
    }

}
