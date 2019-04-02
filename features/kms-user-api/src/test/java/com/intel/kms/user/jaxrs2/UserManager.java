/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

import com.intel.kms.user.UserFilterCriteria;

/**
 *
 * @author jbuhacoff
 */
public interface UserManager {
    CreateUserResponse createUser(CreateUserRequest createUserRequest);
    EditUserResponse editUser(EditUserRequest editUserRequest);
    DeleteUserResponse deleteUser(DeleteUserRequest deleteUserRequest);
    RetrieveUserResponse retrieveUser(RetrieveUserRequest retrieveUserRequest);
    FindUsersResponse findUsers(UserFilterCriteria findUsersRequest);
}
