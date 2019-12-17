/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import java.util.Date;
import org.junit.Test;

/**
 *
 * @author ascrawfo
 */
public class TokenExpireTest {
    String issuedAt = "2016-02-09T17:47:40.866109"; 
    String expires = "2016-02-08T18:47:40Z"; 
    
   
    @Test
    public void isTokenExpired(){ 
        Date currentTime = new Date(); 
        Date expiresLocalTime = getTokenExpiresLocalTime(); 
        boolean result = currentTime.after(expiresLocalTime);  
    }

    public Date getTokenExpiresLocalTime(){     
        Date date = new Date(); 
        Iso8601Date iso = new Iso8601Date(date); 
        Iso8601Date serverNow = iso.valueOf(issuedAt);    
        
        Date clientNow = new Date(); 
        long timeDiff = clientNow.getTime() - serverNow.getTime();   

        Iso8601Date tokenExpiresDate = iso.valueOf(expires); 
        long tokenExpiresTime = tokenExpiresDate.getTime() + timeDiff; 
        Date expiresLocalTime = new Date(tokenExpiresTime); 
        
        return expiresLocalTime; 
    }
}
