/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2.keplerlake;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 *
 * @author nallux
 */
public class KeplerLakeCreateKeysRequest {

    @JsonProperty("descriptor_uri")
    private String descriptorUri;
    @JsonProperty("input")
    private List<InputEntry> input;
    @JsonProperty("registry_url")
    private String registryUrl;
    @JsonProperty("output")
    private List<OutputEntry> output;
    @JsonProperty("realm")
    private String realmName;
    @JsonProperty("engine")
    private String engine;
    @JsonProperty("etag")
    private String etag;
    @JsonProperty("call")
    private String call;
    @JsonProperty("cwd")
    private String cwd;
    @JsonProperty("filemap")
    private Map<String, String> fileMap;
  

    public String getEngine() {
        return engine;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public String getEtag() {
        return etag;
    }

    public void setEtag(String etag) {
        this.etag = etag;
    }

    public String getCall() {
        return call;
    }

    public void setCall(String call) {
        this.call = call;
    }

    public List<OutputEntry> getOutput() {
        return output;
    }

    public void setOutput(List<OutputEntry> output) {
        this.output = output;
    }

    public String getDescriptorUri() {
        return descriptorUri;
    }

    public void setDescriptorUri(String descriptorUri) {
        this.descriptorUri = descriptorUri;
    }

    public String getRegistryUrl() {
        return registryUrl;
    }

    public void setRegistryUrl(String registryUrl) {
        this.registryUrl = registryUrl;
    }

    public List<InputEntry> getInput() {
        return input;
    }

    public void setInput(List<InputEntry> input) {
        this.input = input;
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    public Map<String, String> getFileMap() {
        return fileMap;
    }

    public void setFileMap(Map<String, String> fileMap) {
        this.fileMap = fileMap;
    }

    public String getCwd() {
        return cwd;
    }

    public void setCwd(String cwd) {
        this.cwd = cwd;
    }

   
}
