/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.user.jaxrs;

import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.mtwilson.shiro.file.UserEventHook;


/**
 *
 * @author ascrawfo
 */
public class UserPasswordHook implements UserEventHook {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(UserRepository.class);
     
    @Override
    public void afterCreateUser(String username){ //Creates a new empty user for the UserRepository
        log.debug("Creating user profile {}", username);
        UserRepository userRepo = new UserRepository(); 
        UserFilterCriteria criteria = new UserFilterCriteria();
        User user = new User();
        user.setUsername(username);
        criteria.usernameEqualTo = user.getUsername();
        try{
            UserCollection userCollection = userRepo.search(criteria);
            if (userCollection.getUsers().isEmpty()) {
                //search for username. If not present, create
                userRepo.create(user);
                log.debug("Created user profile: {}", username);           
            }
            else
                log.debug("User profile already exists: {}", username);     
        } catch (Exception ex){
            log.error("Error creating user profile", ex);
        }  
    }
    
    @Override
    public void afterUpdateUser(String username){         
        /*log.debug("Updating user profile {}", username);
        UserRepository userRepo = new UserRepository(); 
        User user = new User(); //User profile created remains empty
        
        try{
            userRepo.create(user);
            log.debug("Created user profile: {}", username);
        }
        catch (Exception ex){
            log.error("UserPasswordHook: Error creating user profile", ex);
        } 
        log.debug("Updating user profile {}", username);
        */
    }    

    @Override
    public void afterDeleteUser(String username) {//Edits the user profile to show access was renived if the access is removed from the command line. DONT DELETE PROFILE
        log.debug("Deleting user profile {}", username);
                
        try{
        UserRepository userRepo = new UserRepository();  
        UserFilterCriteria filterByUsername = new UserFilterCriteria(); 
        filterByUsername.usernameEqualTo = username; 
        UserCollection userCollection = userRepo.search(filterByUsername);
        
        for(User user : userCollection.getUsers()){
            UserLocator locator = new UserLocator();
            locator.id = user.getId();         
            userRepo.delete(locator);
            log.debug("Deleted user profile: {}", username); 
            }
        } catch (Exception ex){
            log.error("Error deleting user profile", ex);
        }      
    }
}
