using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using Alan.Authentication.Modules;

namespace Alan.Authentication
{
    /// <summary>
    /// HttpModule
    /// </summary>
    public class AuthModule : IHttpModule
    {
        public void Dispose()
        {
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += Context_AuthenticateRequest;
        }
        /// <summary>
        /// 替换HttpContext.Current.User实现
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Context_AuthenticateRequest(object sender, EventArgs e)
        {
            var app = sender as HttpApplication;
            if (app == null) { return; }
            app.Context.User = new AuthPrincipal(app.Request);
        }
    }
}
