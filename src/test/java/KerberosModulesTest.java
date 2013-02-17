import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.UsernamePasswordHandler;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
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
import java.util.*;

import static org.junit.Assert.assertTrue;

public class KerberosModulesTest {


    private static Properties testVals;

    @BeforeClass
    public static void initialize() throws IOException
    {
        testVals = new Properties();
        InputStream is = new FileInputStream(
                System.getProperty("user.home") +
                        "/.krbTests/TVals.props");
        testVals.load(is);


        System.setProperty("java.security.krb5.realm", (String) testVals.get("domain"));
        System.setProperty("java.security.krb5.kdc", (String) testVals.get("kdc"));

    }

    @Before
    public void setUp()  {
         Configuration.setConfiguration(new TestConfig());
    }

    static class TestConfig extends Configuration
    {


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

        AppConfigurationEntry[] innerKrbContext()
        {

            String name = "com.sun.security.auth.module.Krb5LoginModule";
            Map<String, String> options = new HashMap<String, String>();

            AppConfigurationEntry krbEntry = new AppConfigurationEntry(name,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
            return new AppConfigurationEntry[]{krbEntry};
        }


    }


    @Test
    public void InnerKrbAuthN () throws Exception
    {

        String samaccount = testVals.get("user").toString();


        UsernamePasswordHandler handler = new UsernamePasswordHandler(samaccount, testVals.get("pass"));
        LoginContext lc = new LoginContext("innerKrbContext", handler);
        lc.login();

        Set<Principal> principals = lc.getSubject().getPrincipals();

        assertTrue("Principals contains sam account", principals.contains(new KerberosPrincipal(samaccount)));

        lc.logout();
    }

    @Test(expected = LoginException.class)
    public void NegInnerKrbAuthN () throws LoginException {

        String samaccount = testVals.get("user").toString();


        UsernamePasswordHandler handler = new UsernamePasswordHandler(samaccount, testVals.get("pass") + "1");
        LoginContext lc = new LoginContext("innerKrbContext", handler);
        lc.login();

        Set<Principal> principals = lc.getSubject().getPrincipals();

        assertTrue("Principals contains sam account", principals.contains(new KerberosPrincipal(samaccount)));

        lc.logout();
    }




}
