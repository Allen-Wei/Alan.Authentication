using System;
using System.Linq;
using System.Security.Principal;
using System.Web;

namespace Alan.Authentication.Modules
{
    /// <summary>
    /// 系统IPrincipal实现
    /// </summary>
    public class AuthPrincipal : IPrincipal
    {
        /// <summary>
        /// 用户标识
        /// </summary>
        private string _uid;
        private AuthPrincipal() { }

        /// <summary>
        /// 初始化
        /// </summary>
        /// <param name="req"></param>
        public AuthPrincipal(HttpRequest req)
        {
            var uid = AuthUtils.Current.GetUid(req);
            this._uid = uid;
        }


        /// <summary>
        /// 用户是否拥有某个角色
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        public bool IsInRole(string role)
        {
            return AuthUtils.Current.IsInRole(HttpContext.Current.Request, role);


        }

        public IIdentity Identity
        {
            get { return new AuthIdentity(this._uid); }
        }

    }

}
