package com.dblfuzzr.jboss.auth.spi;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;


public class DebugLoginModule extends AbstractServerLoginModule {
    private Principal identity;


    @Override
    protected Principal getIdentity() {
         return identity;
    }


    @Override
    public boolean login() throws LoginException
    {
        log.trace("login");
        loginOk = false;


        // If useFirstPass is true, look for the shared password
        if (useFirstPass) {
            Object identity = sharedState.get("javax.security.auth.login.name");
            Object credential = sharedState.get("javax.security.auth.login.password");
            if (identity != null && credential != null) {
                loginOk = true;
                this.identity = (Principal) identity;
                return true;
            } else {
                NameCallback nmc = new NameCallback("Prompt");
                identity = new SimplePrincipal(getUserNameFromCallback(nmc));
                sharedState.put("javax.security.auth.login.name", identity);
                credential = "P".getBytes();
                sharedState.put("javax.security.auth.login.password", credential);

                return true;

            }

        }


        log.error("Can't log user in,  either useFirstPass is not set, or preceding modules failed..");

        return false;
    }

    private String getUserNameFromCallback(NameCallback nmc) throws LoginException {
        try {
            this.callbackHandler.handle(new NameCallback[] {nmc});
        } catch (IOException e) {
           throw new LoginException("Error getting username " + e + e.getStackTrace().toString());
        } catch (UnsupportedCallbackException e) {
            throw new LoginException("Error getting username " + e + e.getStackTrace().toString());
        }
        return nmc.getName();
    }


    @Override
    protected Group[] getRoleSets() throws LoginException {

        SimpleGroup rolesGroup = new SimpleGroup("Roles");
        ArrayList<Principal> groups = new ArrayList<Principal>();

        groups.add(new SimplePrincipal("Managers"));
        groups.add(new SimplePrincipal("Operators"));

        rolesGroup.addMember(groups.get(0));
        rolesGroup.addMember(groups.get(1));

        Group[] roleSets = new Group[1];
        roleSets[0] = rolesGroup;


        return roleSets;
    }




}
