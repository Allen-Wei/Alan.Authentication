using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace Alan.Authentication.Demo
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            Alan.Authentication.AuthUtils.InjectAuth(new Alan.Authentication.Implementation.NormalCookieAuthentication());
            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }
    }
}
