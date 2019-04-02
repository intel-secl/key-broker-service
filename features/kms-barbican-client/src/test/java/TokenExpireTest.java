
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import java.util.Date;
import org.junit.Test;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

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
    /*
    var serverNow = new Date(data.authorization_date);
    var clientNow = new Date();
    self.timediff = clientNow.getTime() - serverNow.getTime();
    var tokenExpiresDate = self.convertServerDateToClientDate(data.not_after); // input: ISO8601 date string,  output: Date object
    self.userProfile.authorizationTokenExpires(tokenExpiresDate.getTime()); // now it's in client time, useful for scheduling timers, because it's adjusted for any time difference between client and server  
    */
    public Date getTokenExpiresLocalTime(){     
        Date date = new Date(); 
        Iso8601Date iso = new Iso8601Date(date); 
        Iso8601Date serverNow = iso.valueOf(issuedAt);    
        
        Date clientNow = new Date(); 
        long timeDiff = clientNow.getTime() - serverNow.getTime();   
        /*
        self.convertServerDateToClientDate = function(serverDateIso8601) { 
        var date = new Date(serverDateIso8601);
        date.addMilliseconds(self.timediff);
        return date;
        };
        */
        Iso8601Date tokenExpiresDate = iso.valueOf(expires); 
        long tokenExpiresTime = tokenExpiresDate.getTime() + timeDiff; 
        Date expiresLocalTime = new Date(tokenExpiresTime); 
        
        return expiresLocalTime; 
    }
}
