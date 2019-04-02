/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.kmip.client.validate;

import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author aakashmX
 */
public class RequestValidator {

    public static List<Fault> validateCreateKey(CreateKeyRequest createKeyRequest) {
        List<Fault> faults = new ArrayList<>();
        if (createKeyRequest.getAlgorithm() == null) {
            faults.add(new MissingRequiredParameter("algorithm"));
            return faults;
        }
        if (!createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            return faults;
        }
        // check AES specific parameters
        if (createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            if (createKeyRequest.getKeyLength() == null) {
                faults.add(new MissingRequiredParameter("keyLength")); // TODO: the "parameter" field of the MissingRequiredParameter class needs to be annotated so a filter can automatically convert it's VALUE from keyLength to key_length (javascript) or keep it as keyLength (xml) or KeyLength (SAML) etc.  ... that's something the jackson mapper doesn't do so we have to ipmlement a custom filter for VALUES taht represent key names.
                return faults;
            }
            if (!ArrayUtils.contains(new int[]{128, 192, 256}, createKeyRequest.getKeyLength())) {
                faults.add(new InvalidParameter("keyLength"));
                return faults;
            }
        }

        return faults;
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
