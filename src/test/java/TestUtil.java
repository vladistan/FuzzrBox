import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: vlad
 * Date: 2/15/13
 * Time: 7:59 AM
 * To change this template use File | Settings | File Templates.
 */
public class TestUtil
{
    public static Principal getPrincipal(final String name)
    {
        return new Principal()
        {
            public String getName()
            {
                return name;
            }
        };
    }

    static Resource getResource()
    {
        return new Resource()
        {
            HashMap<String,Object> contextMap = new HashMap<String, Object>();

            public ResourceType getLayer()
            {
                return ResourceType.POJO;
            }

            public Map<String, Object> getMap()
            {
                return contextMap;
            }

            public void add(String key, Object value)
            {
                contextMap.put(key, value);
            }
        };
    }
}
