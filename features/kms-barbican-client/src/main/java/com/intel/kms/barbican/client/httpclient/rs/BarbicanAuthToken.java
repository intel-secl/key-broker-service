/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.barbican.client.httpclient.rs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.util.Date;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONObject;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;

/**
 *
 * @author ascrawfo
 */
public class BarbicanAuthToken {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory
			.getLogger(BarbicanAuthToken.class);
   
    public String authToken;
    public String barbicanKeystonePublicEndpoint; 
    public String tenantName; 
    public String userName; 
    public String password; 
    public String expires;
    public String issuedAt; 
    public Date expiresLocalTime; 
    
    public BarbicanAuthToken(Configuration configuration){
        barbicanKeystonePublicEndpoint = configuration.get("barbican.keystone.public.endpoint"); 
        tenantName = configuration.get("barbican.tenantname"); 
        userName = configuration.get("barbican.username");
        password = configuration.get("barbican.password");
        
        createAuthToken(barbicanKeystonePublicEndpoint, tenantName, userName, password); 
    }
    
    public String getToken(){ //check if the token has expired before returning 
        if(isTokenExpired()){
            createAuthToken(barbicanKeystonePublicEndpoint, tenantName, userName, password);
            return authToken; 
        }
        else{
            return authToken; 
        }
    }
    
    private boolean isTokenExpired(){ 
        Date currentTime = new Date(); 
        boolean result = currentTime.after(expiresLocalTime); 
        
        return result; 
    }

    private Date getTokenExpiresLocalTime(){     
        Iso8601Date serverNow = Iso8601Date.valueOf(issuedAt);
        
        Date clientNow = new Date(); 
        long timeDiff = clientNow.getTime() - serverNow.getTime();   

        Iso8601Date tokenExpiresDate = Iso8601Date.valueOf(expires); 
        long tokenExpiresTime = tokenExpiresDate.getTime() + timeDiff; 
        Date expiresLocalTime = new Date(tokenExpiresTime); 
        
        return expiresLocalTime; 
    }
    
    
    private void createAuthToken(String barbicanKeystonePublicEndpoint, String tenantName,
			String userName, String password) {
		long start = new Date().getTime();
		//TODO not used after being assigned
		DefaultHttpClient httpClient = new DefaultHttpClient();
		BufferedReader br = null;
		boolean responseHasError = false;

		try {
			
			HttpPost postRequest = new HttpPost( barbicanKeystonePublicEndpoint
					+ "/v2.0/tokens");

			String body = "{\"auth\": {\"tenantName\": \"" + tenantName
					+ "\", \"passwordCredentials\": {\"username\": \""
					+ userName + "\", \"password\": \"" + password + "\"}}}";
			HttpEntity entity = new ByteArrayEntity(body.getBytes("UTF-8"));

			postRequest.setEntity(entity);
			postRequest.setHeader("Content-Type", "application/json");
			postRequest.setHeader("Accept", "application/json");
			HttpResponse response = httpClient.execute(postRequest);
			br = new BufferedReader(new InputStreamReader(
					(response.getEntity().getContent())));

			String output;
			StringBuffer sb = new StringBuffer();

			while ((output = br.readLine()) != null) {
				sb.append(output);
			}
			JSONObject obj = new JSONObject(sb.toString());
			if(obj.has("access")){
				JSONObject jsonObjectAccess = obj.getJSONObject("access");
				if(jsonObjectAccess.has("token")){
					JSONObject property = jsonObjectAccess.getJSONObject(
					"token");
					authToken = property.getString("id");
                                        expires = property.getString("expires"); 
                                        issuedAt = property.getString("issued_at");
                                        expiresLocalTime = getTokenExpiresLocalTime(); 
				}else{
					responseHasError = true;
				}
			}else{
				responseHasError = true;
			}
			httpClient.getConnectionManager().shutdown();
			
		} catch (MalformedURLException e) {
			log.error("Error while creating auth token", e);
		} catch (IOException e) {
			log.error("Error while creating auth token", e);
		}
		finally{		
			if(br != null){
				try {
					br.close();
				} catch (IOException e) {
					log.error("Error closing reader", e);
				}
			}

		}
		long end = new Date().getTime();
		printTimeDiff("createAuthToken", start, end);
		if(responseHasError){
			//throw new BarbicanClientException("Unable to communicate with Barbican at "+ barbicanKeystonePublicEndpoint);
                        log.error("createAuthToken: Error in response.");
                        throw new IllegalStateException("Error in createAuthToken");
		}
	}
    
    private void printTimeDiff(String method, long start, long end) {
		log.debug(method + " took " + (end - start) + " ms");
	} 
}
