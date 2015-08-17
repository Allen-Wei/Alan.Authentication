using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Alan.Authentication.Core;
using Alan.Authentication.Utils;
using System.Web.Security;

namespace Alan.Authentication.Implementation
{
    /// <summary>
    /// 依赖 FormsAuthentication 的实现
    /// </summary>
    public class FormsAuthAuthentication : IAuthentication
    {

        /// <summary>
        /// 获取认证Cookie值
        /// </summary>
        /// <returns></returns>
        public AuthTicket<T> GetTicket<T>(HttpRequest request)
        {
            var cookie = request.Cookies[FormsAuthentication.FormsCookieName];
            if (cookie == null) return null;
            var cookieValue = cookie.Value;
            if (String.IsNullOrWhiteSpace(cookieValue)) return null;
            var ticket = FormsAuthentication.Decrypt(cookieValue);
            if (ticket == null || ticket.Expired) return null;
            var authTicket = ticket.UserData.ParseJson<AuthTicket<T>>();
            if (authTicket == null) return null;
            authTicket.UserId = ticket.Name;
            return authTicket;
        }


        /// <summary>
        /// 获取登录时设置的票据
        /// </summary>
        /// <param name="response">Http响应</param>
        /// <param name="uid">用户标识</param>
        /// <param name="days">有效时间</param>
        /// <param name="data">用户附加数据</param>
        /// <returns>认证票据</returns>
        public Tuple<string, string> SignIn(HttpResponse response, string uid, int days, string[] roles, object data)
        {
            //实际上在这里 AuthTicket.UserId 和 FormsAuthenticationTicket里的 uid 冗余了
            //不过两者最好保持一致
            var dataJson = AuthTicket<object>.Create(uid, roles, data).ToJson();

            var ticket = new FormsAuthenticationTicket(2, uid, DateTime.Now, DateTime.Now.AddDays(days), true, dataJson);
            var cookieValue = FormsAuthentication.Encrypt(ticket);

            var cookieName = FormsAuthentication.FormsCookieName ?? typeof(FormsAuthAuthentication).Name;
            var cookie = new HttpCookie(cookieName)
            {
                Path = "/",
                Domain = FormsAuthentication.CookieDomain,
                HttpOnly = true,
                Value = cookieValue
            };

            response.SetCookie(cookie);
            return Tuple.Create("Set-Cookie", cookie.Value);
        }

        /// <summary>
        /// 获取用户标识
        /// </summary>
        /// <param name="request">Http请求</param>
        /// <returns>用户标识</returns>
        public string GetUid(HttpRequest request)
        {
            var ticket = this.GetTicket<object>(request);
            if (ticket == null) return null;
            return ticket.UserId;
        }

        /// <summary>
        /// 获取用户附加数据
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="request"></param>
        /// <returns></returns>
        public T GetUserData<T>(HttpRequest request)
            where T : class
        {
            var ticket = this.GetTicket<T>(request);
            if (ticket == null) return null;
            return ticket.Data;

        }

        /// <summary>
        /// 退出登录
        /// </summary>
        /// <param name="response"></param>
        public void SignOut(HttpResponse response)
        {
            FormsAuthentication.SignOut();
        }

        /// <summary>
        /// 用户是否已认证
        /// </summary>
        /// <param name="request">Http请求</param>
        /// <returns>是否已认证</returns>
        public bool IsAuthenticated(HttpRequest request)
        {
            return HttpContext.Current.User.Identity.IsAuthenticated;
        }

        /// <summary>
        /// 用户是否拥有某个角色
        /// 根据具体需求可以不实现这个方法
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <param name="roleName">角色名称</param>
        /// <returns>返回是否拥有某个角色</returns>
        public bool IsInRole(HttpRequest request, string roleName)
        {
            var ticket = this.GetTicket<object>(request);
            if (ticket == null) return false;
            var roles = ticket.Roles;
            if (roles == null || roles.Length == 0) return false;
            return roles.Any(role => role.ToLower() == roleName.ToLower());
        }
    }

}
