/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.user;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.repository.FilterCriteria;
import com.intel.mtwilson.jaxrs2.DefaultFilterCriteria;
import javax.ws.rs.QueryParam;

/**
 *
 * @author jbuhacoff
 */
public class UserFilterCriteria extends DefaultFilterCriteria implements FilterCriteria<User> {

    @QueryParam("id")
    public UUID id;
    @QueryParam("usernameEqualTo")
    public String usernameEqualTo;
    @QueryParam("firstNameEqualTo")
    public String firstNameEqualTo;
    @QueryParam("lastNameEqualTo")
    public String lastNameEqualTo;
    @QueryParam("nameContains")
    public String nameContains;
    @QueryParam("emailAddressEqualTo")
    public String emailAddressEqualTo;
    @QueryParam("emailAddressContains")
    public String emailAddressContains;
}
