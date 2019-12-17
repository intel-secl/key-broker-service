/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.file.DirectoryFilter;
import com.intel.kms.integrity.PublicKeyNotary;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.jaxrs2.server.resource.DocumentRepository;
import com.intel.mtwilson.repository.RepositoryCreateException;
import com.intel.mtwilson.repository.RepositoryDeleteException;
import com.intel.mtwilson.repository.RepositoryException;
import com.intel.mtwilson.repository.RepositoryInvalidInputException;
import com.intel.mtwilson.repository.RepositoryRetrieveException;
import com.intel.mtwilson.repository.RepositorySearchException;
import com.intel.mtwilson.repository.RepositoryStoreException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
public class UserRepository implements DocumentRepository<User, UserCollection, UserFilterCriteria, UserLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(UserRepository.class);
    private File directory;
    private ObjectMapper mapper;
    private PublicKeyNotary notary = null;

    public UserRepository() {
        super();
        directory = new File(Folders.repository("users"));
        if (!directory.exists() && !directory.mkdirs()) {
            throw new IllegalStateException("Cannot create user repository directory");
        }
        mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        try {
            notary = new PublicKeyNotary();
        }
        catch(IOException | KeyStoreException e) {
            log.error("Cannot load notary", e);
        }
    }

    public File getDirectoryForUser(UUID id) {
        return new File(directory.getAbsolutePath() + File.separator + id.toString());
    }

    public List<UUID> listUserIds() {
        ArrayList<UUID> list = new ArrayList<>();
        File[] userDirectories = directory.listFiles(new DirectoryFilter());
        if( userDirectories == null ) {
            log.warn("Cannot read directory");
        }
        else {
        for (File userDirectory : userDirectories) {
            if (UUID.isValid(userDirectory.getName())) {
                list.add(UUID.valueOf(userDirectory.getName()));
            }
        }
        }
        return list;
    }

    @Override
    @RequiresPermissions("users:search")
    public UserCollection search(UserFilterCriteria criteria) {
        log.debug("User:Search");
        UserCollection userCollection = new UserCollection();
        try {
            log.debug("user search criteria: {}", mapper.writeValueAsString(criteria));
            List<UUID> list = listUserIds();
            for (UUID userId : list) {
                // read profile 
                User user = readUserProfile(userId);
                // apply filter criteria
                if( criteria.id != null && !(criteria.id.equals(user.getId()))) {
                    continue;
                }
                if (criteria.usernameEqualTo != null && !(criteria.usernameEqualTo.equals(user.getUsername()))) {
                    continue;
                }
                if (criteria.firstNameEqualTo != null && !(user.getContact() != null && criteria.firstNameEqualTo.equals(user.getContact().getFirstName()))) {
                    continue;
                }
                if (criteria.lastNameEqualTo != null && !(user.getContact() != null && criteria.lastNameEqualTo.equals(user.getContact().getLastName()))) {
                    continue;
                }
                if (criteria.nameContains != null && !(user.getContact() != null
                        && (user.getContact().getFirstName() != null && user.getContact().getFirstName().contains(criteria.nameContains))
                        || (user.getContact().getLastName() != null && user.getContact().getLastName().contains(criteria.nameContains)))) {
                    continue;
                }
                if (criteria.emailAddressEqualTo != null && !(user.getContact() != null && criteria.emailAddressEqualTo.equals(user.getContact().getEmailAddress()))) {
                    continue;
                }
                if (criteria.emailAddressContains != null && !(user.getContact() != null && user.getContact().getEmailAddress().contains(criteria.emailAddressContains))) {
                    continue;
                }

                userCollection.getUsers().add(user);
            }
        } catch (Exception ex) {
            log.error("User:Search - Error during User search.", ex);
            throw new RepositorySearchException(ex, criteria);
        }
        log.debug("User:Search - Returning back {} of results.", userCollection.getUsers().size());
        return userCollection;
    }

    private User readUserProfile(UUID userId) throws IOException {
        // reads json file
        File userDirectory = getDirectoryForUser(userId);
        if (!userDirectory.exists()) {
            throw new FileNotFoundException(userId.toString());
        }
        File userProfile = new File(userDirectory.getAbsolutePath() + File.separator + "profile.json");
        if (!userProfile.exists()) {
            throw new FileNotFoundException(userId.toString());
        }
        User user = mapper.readValue(userProfile, User.class);
        return user;
    }

    private void writeUserProfile(User user) throws IOException {
        File userDirectory = getDirectoryForUser(user.getId());
        if (!userDirectory.exists() && !userDirectory.mkdirs()) {
            throw new FileNotFoundException(user.getId().toString());
        }
        // automatically notarize user submitted transfer public key 
        if( user.getTransferKeyPem() != null && user.getTransferKeyPem().startsWith("-----BEGIN PUBLIC KEY-----")) {
            try {
                X509Certificate certificate = notary.certifyTransferKey(user.getTransferKey(), user.getUsername());
                user.setTransferKey(certificate);
            }
            catch(CryptographyException | CertificateException e) {
                throw new IOException(e);
            }
        }
        
        File userProfile = new File(userDirectory.getAbsolutePath() + File.separator + "profile.json");
        mapper.writeValue(userProfile, user);
        
        Path path = Paths.get(userDirectory.getAbsolutePath() + File.separator + "profile.json");
        FileOwnerAttributeView foav = Files.getFileAttributeView(path, FileOwnerAttributeView.class);
        UserPrincipalLookupService upls = FileSystems.getDefault().getUserPrincipalLookupService();
        UserPrincipal newOwner = upls.lookupPrincipalByName("kms");
        foav.setOwner(newOwner);
        Files.setOwner(path, newOwner);
        GroupPrincipal targetGroupPrincipal = upls.lookupPrincipalByGroupName("kms");
        Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS)
                .setGroup(targetGroupPrincipal);
        
    }

    private void deleteUserProfile(UUID userId) throws IOException {
        File userDirectory = getDirectoryForUser(userId);
        File userProfile = new File(userDirectory.getAbsolutePath() + File.separator + "profile.json");
        userProfile.delete();
        userDirectory.delete();
    }

    @Override
    @RequiresPermissions("users:retrieve")
    public User retrieve(UserLocator locator) {
        if (locator == null || locator.id == null) {
            return null;
        }
        log.debug("User:Retrieve - Got request to retrieve User with id {}.", locator.id);
        try {
            User user = readUserProfile(locator.id);
            return user;
        } catch (Exception ex) {
            log.error("User:Retrieve - Error during User retrieval.", ex);
            throw new RepositoryRetrieveException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("users:store")
    public void store(User item) {
        if (item == null || item.getId() == null) {
            throw new RepositoryInvalidInputException();
        }
        log.debug("User:Store - Got request to update User with id {}.", item.getId().toString());
        UserLocator locator = new UserLocator();
        locator.id = item.getId();

        try {
            writeUserProfile(item);
            log.debug("User:Store - Updated the User with id {} successfully.", item.getId().toString());
        } catch (Exception ex) {
            log.error("User:Store - Error during User update.", ex);
            throw new RepositoryStoreException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("users:create")
    public void create(User item) {
        log.debug("User:Create - Got request to create a new User.");
        UserLocator locator = new UserLocator();
        if( item.getId() == null ) {
            item.setId(new UUID());
        }
        locator.id = item.getId();
        try {
            writeUserProfile(item);
            log.debug("User:Create - Created the User {} successfully.", item.getId().toString());
        } catch (Exception ex) {
            log.error("User:Create - Error during role creation.", ex);
            throw new RepositoryCreateException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("users:delete")
    public void delete(UserLocator locator) {
        if (locator == null || locator.id == null) {
            return;
        }
        log.debug("User:Delete - Got request to delete User with id {}.", locator.id.toString());
        try {
            deleteUserProfile(locator.id);
            log.debug("User:Delete - Deleted the User with id {} successfully.", locator.id.toString());
        } catch (Exception ex) {
            log.error("User:Delete - Error during User deletion.", ex);
            throw new RepositoryDeleteException(ex, locator);
        }
    }

    @Override
    @RequiresPermissions("users:delete,search")
    public void delete(UserFilterCriteria criteria) {
        log.debug("User:Delete - Got request to delete User by search criteria.");
        UserCollection objCollection = search(criteria);
        try {
            for (User obj : objCollection.getUsers()) {
                UserLocator locator = new UserLocator();
                locator.id = obj.getId();
                delete(locator);
            }
        } catch (RepositoryException re) {
            throw re;
        } catch (Exception ex) {
            log.error("User:Delete - Error during User deletion.", ex);
            throw new RepositoryDeleteException(ex);
        }
    }
}
