using System;
using System.Web;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Alan.Authentication.Core;
using Alan.Authentication.Implementation;
using System.Globalization;

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


        /// <summary>
        /// 创建Cookie Value
        /// </summary>
        /// <param name="name">Cookie 名称</param>
        /// <param name="value">Cookie 值</param>
        /// <param name="expire">Cookie 过期时间</param>
        /// <param name="path">Cookie 路径</param>
        /// <param name="domain">Cookie 域名</param>
        /// <returns></returns>
        public static string CreateCookieValue(string name, string value, DateTime expire, string path)
        {
            var expiresValue = String.Format("{0} GMT", expire.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.CreateSpecificCulture("en-US")));
            var cookieValue = String.Format("{0}={1}; Expires={2}; Path={3}; HttpOnly", name, value, expiresValue, path);
            return cookieValue;
        }
    }
}
