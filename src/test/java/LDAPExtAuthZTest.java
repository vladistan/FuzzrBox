import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.Resource;
import org.junit.Before;
import org.junit.Test;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;

import javax.security.auth.Subject;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Properties;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LDAPExtAuthZTest {

    private final String securityDomainName = "LdapAuthN";
    private final String configFile = "config/ldapExtAuthZ.conf";
    private static Properties testVals;


    private PicketBoxConfiguration idtrustConfig;
    private AuthenticationManager am;
    private Subject subject;
    private AuthorizationManager authzM;


    @Before
    public void setup() throws IOException {
        SecurityFactory.prepare();

        //Without this simple tests don't work...
        System.setProperty("jboss.security.disable.secdomain.option","true");


        testVals = new Properties();
        InputStream is = new FileInputStream(
                System.getProperty("user.home") +
                        "/.krbTests/TVals.props");
        testVals.load(is);


        idtrustConfig = new PicketBoxConfiguration();
        idtrustConfig.load(configFile);

        am = SecurityFactory.getAuthenticationManager(securityDomainName);
        subject = new Subject();
        authzM = SecurityFactory.getAuthorizationManager(securityDomainName);
    }

    @Test
    public void initOK()
    {
        assertNotNull(am);
        assertNotNull(authzM);

    }

    @Test
    public void simpleAuth() throws AuthorizationException {


        Principal principal = TestUtil.getPrincipal(testVals.get("samaccount").toString());
        Object credential =  "";


        boolean result = am.isValid(principal, credential, subject);
        assertTrue("Valid Auth", result);
        assertTrue("Subject has principals", subject.getPrincipals().size() > 0);

    }

   @Test
    public void simpleNegAuth()
    {
        Principal principal = TestUtil.getPrincipal(testVals.get("samaccount").toString()+ "1") ;
        Object credential = new String("passv");

        boolean result = am.isValid(principal, credential, subject);
        assertFalse("Valid Auth", result);
        assertTrue("Subject has principals", subject.getPrincipals().size() == 0);

    }

    @Test
    public void simpleAuthZ() throws AuthorizationException {

        Principal principal = TestUtil.getPrincipal(testVals.get("samaccount").toString());
        Object credential =  "";


        am.isValid(principal, credential, subject);

        Resource resource = TestUtil.getResource();
        int decision = authzM.authorize(resource, subject);
        assertTrue(decision == AuthorizationContext.PERMIT);
    }

    @Test(expected = AuthorizationException.class)
    public void simpleNegAuthZ() throws AuthorizationException {

        Principal principal = TestUtil.getPrincipal(testVals.get("samaccount2").toString());
        Object credential =  "";

        boolean result = am.isValid(principal, credential, subject);

        assertTrue("Valid Auth", result);
        assertTrue("Subject has principals", subject.getPrincipals().size() > 0);


        Resource resource = TestUtil.getResource();
        authzM.authorize(resource, subject);
    }


}
