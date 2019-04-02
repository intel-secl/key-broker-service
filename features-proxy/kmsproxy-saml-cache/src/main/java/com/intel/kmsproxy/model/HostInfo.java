package com.intel.kmsproxy.model;
import com.fasterxml.jackson.annotation.JsonProperty;

public class HostInfo {
    
    @JsonProperty("hardwareUUID")
    String hardwareUUID;

    public String getHardwareUUID() {
        return hardwareUUID;
    }

    public void setHardwareUUID(String hardwareUUID) {
        this.hardwareUUID = hardwareUUID;
    }
}
