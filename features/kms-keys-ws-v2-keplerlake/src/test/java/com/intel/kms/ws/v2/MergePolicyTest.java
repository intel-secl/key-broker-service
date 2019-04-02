/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.kms.keplerlake.Policy;
import com.intel.kms.keplerlake.PolicyUri;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author kchinnax
 */
public class MergePolicyTest {

    public static void main(String arg[]) throws IOException {
        String policyJson1 = "{\n"
                + "	\"meta\": {\n"
                + "		\"id\": \"1e993d3b-936c-4db1-b1d5-f274fcfef7fa\",\n"
                + "		\"version\": 1\n"
                + "	},\n"
                + "	\"label\": \"policy for my protected dataset 1234\",\n"
                + "	\"description\": \"Intel policy\",\n"
                + "	\"validity\": {\n"
                + "		\"notBefore\": \"2016-07-18T09:23:34+00:00\",\n"
                + "		\"notAfter\": null\n"
                + "	},\n"
                + "	\"permission\": {\n"
                + "		\"key_transfer\": {\n"
                + "			\"flavor\": [{\n"
                + "				\"label\": \"Hardened CentOS 7\"\n"
                + "			},\n"
                + "			{\n"
                + "				\"label\": \"Key Escrow on ClearLinux 8830\"\n"
                + "			}]\n"
                + "		}\n"
                + "	}\n"
                + "}";

        String policyJson2 = "{\n"
                + "	\"meta\": {\n"
                + "		\"id\": \"1x993d3b-936c-4db1-b1d5-f274fcfef7fx\",\n"
                + "		\"version\": 1\n"
                + "	},\n"
                + "	\"label\": \"policy for my protected dataset3421\",\n"
                + "	\"description\": \"Intel policy\",\n"
                + "	\"validity\": {\n"
                + "		\"notBefore\": \"2016-07-18T09:23:34+00:00\",\n"
                + "		\"notAfter\": null\n"
                + "	},\n"
                + "	\"allOf\": [{\n"
                + "		\"uri\": \"urn:etcd:/realm/example.com/policy/1e993d3b-936c-4db1-b1d5-f274fcfef7fa\"\n"
                + "	},\n"
                + "	{\n"
                + "		\"uri\": \"urn:etcd:/realm/example.com/policy/d5d335cc-9780-4f10-b73c-ef313db0002a\"\n"
                + "	}],\n"
                + "	\"permission\": {\n"
                + "		\"key_transfer\": {\n"
                + "			\"flavor\": [{\n"
                + "				\"label\": \"Hardened CentOS 7\"\n"
                + "			},\n"
                + "			{\n"
                + "				\"label\": \"Key Escrow on ClearLinux 8830\"\n"
                + "			}]\n"
                + "		}\n"
                + "	}\n"
                + "}";
        ObjectMapper mapper = new ObjectMapper();
        System.out.println("mapper");
        Policy policy1 = mapper.readValue(policyJson1, Policy.class);
        Policy policy2 = mapper.readValue(policyJson2, Policy.class);
        System.out.println("policy");
        if (policy1 != null) {
            System.out.println("get label::" + policy1.getMeta().any().get("id"));
        }
        List<Policy> policyList = new ArrayList<>();
        policyList.add(policy1);
        policyList.add(policy2);

        List<String> inputPolicyIdList = new ArrayList<>();
        String inputPolicyId;
        for (Policy inputPolicy : policyList) {

            System.out.println("inputPolicy:::" + inputPolicy.getMeta().any().get("id"));
            System.out.println("allOf :::" + inputPolicy.getAllOf());
            if (inputPolicy.getAllOf() != null && inputPolicy.getAllOf().size() > 0) {
                System.out.println("iffff");
                for (PolicyUri policyUri : inputPolicy.getAllOf()) {
                    inputPolicyId = policyUri.getPolicyUri().substring(policyUri.getPolicyUri().lastIndexOf("/") + 1);
                    System.out.println("input policy id: " + inputPolicyId);
                    if (!inputPolicyIdList.contains(inputPolicyId)) {
                        System.out.println("inputlist not contains policy id");
                        inputPolicyIdList.add(inputPolicyId);
                    }
                }
            } else if (inputPolicy.getMeta() != null && inputPolicy.getMeta().any().size() > 0) {
                System.out.println("elseee");
                if (inputPolicy.getMeta().any().containsKey("id")) {
                    inputPolicyId = (String)inputPolicy.getMeta().any().get("id");
                    System.out.println("2nd policy : " + inputPolicyId);
                    if (!inputPolicyIdList.contains(inputPolicyId)) {
                        inputPolicyIdList.add(inputPolicyId);
                    }

                }

            }
            System.out.println("list id size:" + inputPolicyIdList.size());
            for (String pids : inputPolicyIdList) {
                System.out.println("Ids:::" + pids);
            }

        }
    }
}
