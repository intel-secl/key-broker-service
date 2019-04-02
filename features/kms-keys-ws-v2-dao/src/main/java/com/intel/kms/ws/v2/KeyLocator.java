/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.ws.v2.api.Key;
import com.intel.mtwilson.repository.Locator;
import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class KeyLocator implements Locator<Key>{

    @PathParam("id")
    public UUID id;

    @Override
    public void copyTo(Key item) {
        if( id != null ) {
            item.setId(id);
        }
    }
    
}
