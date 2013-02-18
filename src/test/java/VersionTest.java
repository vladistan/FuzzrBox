import com.dblfuzzr.jboss.auth.spi.VersionInfo;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;

/**
 * User: vlad
 * Created : 2/18/13 8:09 AM
 *
 * This is a dummy test to test version class. Since that class contains no logic we can't test that much
 *
 */
public class VersionTest {

         @Test
         public void Fields()
         {

             assertEquals("Copyright (c) DblFuzzr,LLC 2013",VersionInfo.VersionCopyright);
             assertEquals("Fuzzrbox",VersionInfo.VersionProductName);
             assertEquals("Java Classes For Fuzzrbox",VersionInfo.VersionFileDesc);

         }


}
