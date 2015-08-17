using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace Alan.Authentication.Modules
{

    /// <summary>
    /// 系统IIdentity实现
    /// </summary>
    public class AuthIdentity : IIdentity
    {
        /// <summary>
        /// 用户表示
        /// </summary>
        private string _uid;
        public AuthIdentity(string uid) { this._uid = uid; }


        public string AuthenticationType
        {
            get { return this.GetType().FullName; }
        }

        /// <summary>
        /// 是否已认证
        /// </summary>
        public bool IsAuthenticated
        {
            get { return !String.IsNullOrWhiteSpace(this._uid); }
        }

        public string Name
        {
            get { return this._uid; }
        }
    }

}
