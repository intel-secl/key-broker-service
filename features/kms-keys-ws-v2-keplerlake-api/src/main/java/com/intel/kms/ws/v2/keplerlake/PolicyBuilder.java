/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2.keplerlake;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Set;

/**
 *
 * @author nallux
 */
public class PolicyBuilder {

    static ObjectMapper objectMapper = new ObjectMapper();

    public static LinkedHashMap buildMergePolicy(List<LinkedHashMap> inputPolicies) {

       
        return procesLinkedHashMap(inputPolicies);
      

    }

    private static LinkedHashMap procesLinkedHashMap(List<LinkedHashMap> inputPolicies) {

        LinkedHashMap resultLinkedHashMap = new LinkedHashMap();
        Set keys = inputPolicies.get(0).keySet();
        for (Object key : keys) {

            boolean commonKey = false;
            ArrayList<LinkedHashMap> commonKeyResults = new ArrayList<LinkedHashMap>();
            for (int i = 1; i < inputPolicies.size(); i++) {
                Set keys2 = inputPolicies.get(i).keySet();
                if (keys2.contains(key)) {
                    commonKey = true;
                    commonKeyResults.add((LinkedHashMap) inputPolicies.get(i).get(key));
                    
                }
            }

            if (!commonKey) {
                resultLinkedHashMap.put(key, inputPolicies.get(0).get(key));
				
            } else if (inputPolicies.get(1).get(key) instanceof LinkedHashMap) {

                resultLinkedHashMap.put(key, procesLinkedHashMap(commonKeyResults));
            } else if (inputPolicies.get(1).get(key) instanceof ArrayList) {
                List<ArrayList> items = new ArrayList<ArrayList>();
                for (int k = 0; k <= inputPolicies.size(); k++) {
                    items.add((ArrayList) inputPolicies.get(k).get(key));
                }
                List result = processObjectArray(items);
                // ArrayList result = processObjectArray((ArrayList) linkedHashMap.get(key), (ArrayList) linkedHashMap2.get(key));
                resultLinkedHashMap.put(key, result);
                return resultLinkedHashMap;
            }

        }
        return resultLinkedHashMap;
    }

    private static List processObjectArray(List<ArrayList> arrayObjects) {
        List resultList = new ArrayList();
        List firstArrayObjects = arrayObjects.get(0);
        for (Object obj : firstArrayObjects) {
            HashMap actualMap = (HashMap) obj;
            String valueOfFirst = actualMap.get(actualMap.keySet().toArray()[0]).toString();
            for (int index = 1; index <= arrayObjects.size(); index++) {
                for (Object obj2 : arrayObjects.get(index)) {
                    HashMap actualMap2 = (HashMap) obj2;
                    String valueOfSecond = actualMap2.get(actualMap2.keySet().toArray()[0]).toString();
                    if (valueOfSecond != null
                            && valueOfFirst.equalsIgnoreCase(valueOfSecond)) {
                        resultList.add(actualMap);
                        break;
                    }
                }
            }
        }
        return resultList;

    }
}
