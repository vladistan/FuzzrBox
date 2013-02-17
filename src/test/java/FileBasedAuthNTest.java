import org.junit.Before;
import org.junit.Test;

import org.jboss.security.authorization.AuthorizationException;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;


import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FileBasedAuthNTest {

    private final String securityDomainName = "FileBased";
    private final String configFile = "config/filesAuthN.conf";
    private PicketBoxConfiguration idtrustConfig;
    private AuthenticationManager am;
    private Subject subject;


    @Before
    public void setup()
    {
        SecurityFactory.prepare();

        idtrustConfig = new PicketBoxConfiguration();
        idtrustConfig.load(configFile);

        am = SecurityFactory.getAuthenticationManager(securityDomainName);
        subject = new Subject();
    }

    @Test
    public void initOK()
    {
        assertNotNull(am);
    }

    @Test
    public void simpleAuth() throws AuthorizationException {
        Principal principal = TestUtil.getPrincipal("anil");
        Object credential = new String("pass");

        boolean result = am.isValid(principal, credential, subject);
        assertTrue("Valid Auth", result);
        assertTrue("Subject has principals", subject.getPrincipals().size() > 0);
    }

   @Test
    public void simpleNegAuth()
    {
        Principal principal = TestUtil.getPrincipal("anil");
        Object credential = new String("passv");

        boolean result = am.isValid(principal, credential, subject);
        assertFalse("Valid Auth", result);
        assertTrue("Subject has principals", subject.getPrincipals().size() == 0);

    }

}
