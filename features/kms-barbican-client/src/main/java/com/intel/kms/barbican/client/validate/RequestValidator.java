/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.validate;

import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.cipher.SecretKeyReport;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author soakx
 */
public class RequestValidator {

    public static Collection<Fault> validateCreateKey(CreateKeyRequest createKeyRequest) {
        SecretKeyReport report = new SecretKeyReport(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());
        return report.getFaults();
    }

    public static List<Fault> validateTransferKey(TransferKeyRequest transferKeyRequest) {
        List<Fault> faults = new ArrayList<>();
        if (StringUtils.isBlank(transferKeyRequest.getKeyId())) {
            faults.add(new MissingRequiredParameter("keyId"));
        }
        return faults;
    }

    public static List<Fault> validateRegisterKey(RegisterKeyRequest registerKeyRequest) {
        List<Fault> faults = new ArrayList<>();
        if (registerKeyRequest.getKey() == null || ArrayUtils.isEmpty(registerKeyRequest.getKey())) {
            faults.add(new MissingRequiredParameter("key"));
        }
        return faults;
    }

    public static List<Fault> validateDeleteKey(DeleteKeyRequest deleteKeyRequest) {
        List<Fault> faults = new ArrayList<>();
        if (StringUtils.isEmpty(deleteKeyRequest.getKeyId())) {
            faults.add(new MissingRequiredParameter("keyId"));
        }
        return faults;
    }

}
