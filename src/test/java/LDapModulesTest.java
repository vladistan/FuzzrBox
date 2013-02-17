import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.UsernamePasswordHandler;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertTrue;

public class LDapModulesTest {


    private static Properties testVals;
    public static final String LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String ROLE_ATTRIBUTE_ID = "memberOf";
    public static final String JBOSS_LDAPEXT_LOGIN_SPI = "org.jboss.security.auth.spi.LdapExtLoginModule";
    public static final String SAMACCCOUNT_FILTER = "(sAMAccountName={0})";

    @Before
    public void setUp() throws IOException {


        testVals = new Properties();
        InputStream is = new FileInputStream(
                System.getProperty("user.home") +
                "/.krbTests/TVals.props");
        testVals.load(is);


        Configuration.setConfiguration(new TestConfig());

    }

    static class TestConfig extends Configuration
    {

        public static final String JBOSS_LDAP_LOGIN_SPI = "org.jboss.security.auth.spi.LdapLoginModule";
        public static final String CN_ATTR = "cn";

        public void refresh()
        {
        }

        public AppConfigurationEntry[] getAppConfigurationEntry(String name)
        {
            AppConfigurationEntry[] entry = null;
            try
            {
                Class[] parameterTypes = {};
                Method m = getClass().getDeclaredMethod(name, parameterTypes);
                Object[] args = {};
                entry = (AppConfigurationEntry[]) m.invoke(this, args);
            }
            catch(Exception e)
            {
            }
            return entry;
        }


        AppConfigurationEntry[] LDAPloginUsingCN()
        {

            String baseCtx = testVals.getProperty("baseContext");
            String dnxPfx  = CN_ATTR+"=";
            String dnSfx   = testVals.getProperty("dnSuffix");


            String name = JBOSS_LDAP_LOGIN_SPI;
            HashMap<String, String> options = new HashMap<String, String>();

            options.put("java.naming.factory.initial", LDAP_CTX_FACTORY);
            options.put("java.naming.provider.url", testVals.getProperty("ldapUrl"));

            options.put("java.naming.security.authentication", "simple");
            options.put("baseCtxDN", baseCtx);
            options.put("principalDNPrefix", dnxPfx);
            options.put("principalDNSuffix", dnSfx);


            AppConfigurationEntry ace = new AppConfigurationEntry(name,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            return new AppConfigurationEntry[]{ace};
        }

        AppConfigurationEntry[] LDAPcheckBindAccount()
        {
            String name = JBOSS_LDAP_LOGIN_SPI;
            String dnxPfx   = CN_ATTR + "=";
            String dnSfx    = testVals.getProperty("bindDnSuffix");
            String bindPass = testVals.getProperty("bindpass");


            HashMap<String,String> options = new HashMap<String, String>();

            options.put("java.naming.factory.initial", LDAP_CTX_FACTORY);
            options.put("java.naming.provider.url", testVals.getProperty("ldapUrl"));

            options.put("java.naming.security.authentication", "simple");
            options.put("java.naming.security.credentials", bindPass);
            options.put("principalDNPrefix", dnxPfx);
            options.put("principalDNSuffix", dnSfx);

            AppConfigurationEntry ace = new AppConfigurationEntry(name,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            return new AppConfigurationEntry[]{ace};
        }

        AppConfigurationEntry[] LDAPloginAndRolesUsingCN()
        {
            String name = JBOSS_LDAP_LOGIN_SPI;

            String dnxPfx  = CN_ATTR+"=";
            String dnSfx   = testVals.getProperty("dnSuffix");
            String rolesCtxDN = testVals.getProperty("rolesCtxDN");


            HashMap<String,String> options = new HashMap<String, String>();

            options.put("java.naming.factory.initial", LDAP_CTX_FACTORY);
            options.put("java.naming.provider.url", testVals.getProperty("ldapUrl"));

            options.put("java.naming.security.authentication", "simple");

            options.put("principalDNPrefix", dnxPfx);
            options.put("principalDNSuffix", dnSfx);


            options.put("uidAttributeID", CN_ATTR);

            options.put("rolesCtxDN", rolesCtxDN);
            options.put("roleAttributeID", ROLE_ATTRIBUTE_ID);
            options.put("roleAttributeIsDN","true");



            AppConfigurationEntry ace = new AppConfigurationEntry(name,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            return new AppConfigurationEntry[]{ace};
        }


        AppConfigurationEntry[] LDAPloginAndRolesUsingSamaccount()
        {
            String name = JBOSS_LDAPEXT_LOGIN_SPI;

            HashMap<String,String> options = new HashMap<String, String>();

            String dnxPfx  = CN_ATTR+"=";
            String dnSfx   = testVals.getProperty("dnSuffix");
            String rolesCtxDN = testVals.getProperty("rolesCtxDN");


            String bindDN   = testVals.getProperty("bindDN");
            String bindPass = testVals.getProperty("bindpass");
            String baseCtx = testVals.getProperty("baseContext");


            options.put("java.naming.factory.initial", LDAP_CTX_FACTORY);
            options.put("java.naming.provider.url", testVals.getProperty("ldapUrl"));
            options.put("java.naming.security.authentication", "simple");


            options.put("principalDNPrefix", dnxPfx);
            options.put("principalDNSuffix", dnSfx);
            options.put("uidAttributeID", CN_ATTR);
            options.put("rolesCtxDN", rolesCtxDN);

            options.put("roleAttributeID", ROLE_ATTRIBUTE_ID);

            options.put("bindDN", bindDN);
            options.put("bindCredential",bindPass);


            options.put("baseCtxDN",baseCtx);

            options.put("roleAttributeIsDN","true");
            options.put("baseFilter", SAMACCCOUNT_FILTER);
            options.put("roleFilter", SAMACCCOUNT_FILTER);



            AppConfigurationEntry ace = new AppConfigurationEntry(name,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            return new AppConfigurationEntry[]{ace};
        }


    }


    @Test
    public void LDAPloginAndRolesUsingSamaccount() throws Exception
    {
        SimplePrincipal role1 = new SimplePrincipal(testVals.getProperty("role1"));
        SimplePrincipal role2 = new SimplePrincipal(testVals.getProperty("role2"));


        String samaccount = testVals.get("samaccount").toString();


        UsernamePasswordHandler handler = new UsernamePasswordHandler(samaccount, testVals.get("pass"));
        LoginContext lc = new LoginContext("LDAPloginAndRolesUsingSamaccount", handler);
        lc.login();

        Subject subject = lc.getSubject();

        Set<Group> groups = subject.getPrincipals(Group.class);
        Set<Principal> principals = subject.getPrincipals();


        assertTrue("Principals contains sam account", principals.contains(new SimplePrincipal(samaccount)));


        Iterator<Group> gIter = groups.iterator();
        gIter.next();
        Group roles = gIter.next();


        assertTrue("Contains Role #1", roles.isMember(role1));
        assertTrue("Contains Role #2", roles.isMember(role2));


        lc.logout();
    }



    @Test
    public void LDAPloginAndRolesUsingCN() throws LoginException {

        String userCN = testVals.get("userCN").toString();
        Object pass = testVals.get("pass");

        SimplePrincipal role1 = new SimplePrincipal(testVals.getProperty("role1"));
        SimplePrincipal role2 = new SimplePrincipal(testVals.getProperty("role2"));


        UsernamePasswordHandler handler = new UsernamePasswordHandler(userCN, pass);


        LoginContext lc = new LoginContext("LDAPloginAndRolesUsingCN", handler);
        lc.login();

        Subject subject = lc.getSubject();

        Set<Group> groups = subject.getPrincipals(Group.class);
        assertTrue("Principals contains CN", subject.getPrincipals().contains(new SimplePrincipal(userCN)));
        assertTrue("Principals contains Roles", groups.contains(new SimplePrincipal("Roles")));

        Iterator<Group> pIter = groups.iterator();
        pIter.next();
        Group roles = pIter.next();

        assertTrue("Contains Role #1", roles.isMember(role1));
        assertTrue("Contains Role #2", roles.isMember(role2));

        lc.logout();
    }


    @Test
    public void LoginUsingCN() throws LoginException {

        String userCN = testVals.get("userCN").toString();
        Object pass = testVals.get("pass");

        UsernamePasswordHandler handler = new UsernamePasswordHandler(userCN,pass);

        LoginContext lc = new LoginContext("LDAPloginUsingCN", handler);
        lc.login();

        Subject subject = lc.getSubject();

        Set<Group> groups = subject.getPrincipals(Group.class);
        assertTrue("Principals contains user name", subject.getPrincipals().contains(new SimplePrincipal(userCN)));
        assertTrue("Principals contains Roles", groups.contains(new SimplePrincipal("Roles")));

        lc.logout();
    }


    @Test
    public void isBindAccountGood() throws LoginException {

        String bindaccount = (String) testVals.get("bindaccount");
        UsernamePasswordHandler handler = new UsernamePasswordHandler(
                bindaccount, testVals.get("bindpass"));

        LoginContext lc = new LoginContext("LDAPcheckBindAccount", handler);
        lc.login();

        Subject subject = lc.getSubject();

        Set<Group> groups = subject.getPrincipals(Group.class);
        assertTrue("Principals contains username ", subject.getPrincipals().contains(new SimplePrincipal(bindaccount)));
        assertTrue("Principals contains Roles", groups.contains(new SimplePrincipal("Roles")));

        lc.logout();
    }


    }
