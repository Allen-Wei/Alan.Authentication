using System;
using System.Web;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Alan.Authentication.Core;
using Alan.Authentication.Implementation;

namespace Alan.Authentication
{
    /// <summary>
    ///  Alan.Authentication 实用方法
    /// </summary>
    public class AuthUtils
    {
        public static IAuthentication Current;

        static AuthUtils()
        {
            Current = new FormsAuthAuthentication();
        }
        /// <summary>
        /// 修改默认 AlanAuthentication 实现
        /// </summary>
        /// <param name="auth"></param>
        public static void InjectAuth(IAuthentication auth)
        {
            Current = auth;
        }

    }
}
