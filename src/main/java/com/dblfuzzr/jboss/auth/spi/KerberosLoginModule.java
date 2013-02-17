package com.dblfuzzr.jboss.auth.spi;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.negotiation.common.CommonLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Map;

/**
 * User: vlad
 * Date: 2/3/13
 * Time: 7:04 AM
 */
public class KerberosLoginModule extends CommonLoginModule {


        private Principal identity = null;

        // private Principal identity = new JAASSecurityManager.SimplePrincipal("DebugIdentity");

        @Override
        protected Principal getIdentity() {
            return identity;
        }

        @Override
        public void initialize(Subject subject, CallbackHandler callbackHandler,
                               Map sharedState, Map options)
        {
            this.subject = subject;
            this.callbackHandler = callbackHandler;
            this.sharedState = sharedState;
            this.options = options;
            log = Logger.getLogger(getClass());
            log.trace("initialize");


            // Check for a custom Principal implementation
            principalClassName = (String) options.get("principalClass");


            String passwordStacking = (String) options.get("password-stacking");
            if( passwordStacking != null && passwordStacking.equalsIgnoreCase("useFirstPass") )
                useFirstPass = true;


            // Check for unauthenticatedIdentity option.
            String name = (String) options.get("unauthenticatedIdentity");
            if( name != null )
            {
                try
                {
                    unauthenticatedIdentity = createIdentity(name);
                    log.trace("Saw unauthenticatedIdentity="+name);
                }
                catch(Exception e)
                {
                    log.warn("Failed to create custom unauthenticatedIdentity", e);
                }
            }

            String kdc = (String) options.get("kdc");
            if ( kdc != null )
            {
                log.trace("Setting KDC to ="+kdc);
                System.setProperty("java.security.krb5.kdc", kdc);
            }

            String realm = (String) options.get("realm");
            if ( realm != null )
            {
                log.trace("Setting Kerberos Realm to ="+realm);
                System.setProperty("java.security.krb5.kdc", realm);
                System.setProperty("java.security.krb5.realm", realm);
            }

        }

        @Override
        public boolean login() throws LoginException
        {
            log.trace("login");
            loginOk = false;

            //TODO: Repackage password callback handler




            try {


                LoginContext lc = new LoginContext("innerKrbContext", this.callbackHandler);
                lc.login();

                Subject lSubj = lc.getSubject();

                if ( lSubj == null )
                {
                    return false;
                }


                KerberosPrincipal prc = lSubj.getPrincipals(KerberosPrincipal.class).iterator().next();

                try {
                    this.identity = createIdentity(prc.getName());
                } catch (Exception e) {
                    log.debug("Failed to create principal", e);
                    throw new LoginException(ErrorCodes.PROCESSING_FAILED + "Failed to create principal: " + e.getMessage());
                }


                // If useFirstPass is true, look for the shared password
                if( useFirstPass == true  )
                {
                    char[] credential =  "PASSWORD*OBSCURED".toCharArray();

                    sharedState.put("javax.security.auth.login.name",this.identity);
                    sharedState.put("javax.security.auth.login.password",credential);
                }

                this.loginOk = true;
                return true;

            }
            catch ( LoginException e  )
            {
                if ( log.isDebugEnabled())
                {
                    log.debug("Invalid Kerberos login. "  + e.getStackTrace());
                }
                throw e;
            }


        }


        @Override
        protected Group[] getRoleSets() throws LoginException {

            SimpleGroup rolesGroup = new SimpleGroup("Roles");
            ArrayList<Principal> groups = new ArrayList();

            groups.add(new SimplePrincipal("RealmUser"));
            groups.add(new SimplePrincipal("valid-user"));

            rolesGroup.addMember(groups.get(0));
            rolesGroup.addMember(groups.get(1));

            Group[] roleSets = new Group[1];
            roleSets[0] = rolesGroup;


            return roleSets;
        }
}



