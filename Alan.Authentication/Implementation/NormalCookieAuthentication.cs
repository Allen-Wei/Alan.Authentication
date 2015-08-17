using System;
using System.Configuration;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Alan.Authentication.Core;
using Alan.Authentication.Utils;

namespace Alan.Authentication.Implementation
{
    public class NormalCookieAuthentication : IAuthentication

    {
        /// <summary>
        /// Cookie的名字
        /// </summary>
        private string CookieName { get { return this.GetType().Name; } }

        /// <summary>
        /// AES加密的密钥 16字节长度
        /// 优先从配置节[Authentication-AESKey]获取.
        /// </summary>
        private byte[] AesKey
        {
            get
            {
                var keyValue = ConfigurationSettings.AppSettings["Authentication-AESKey"] ?? "0a2666796b5a4127";
                return Encoding.UTF8.GetBytes(keyValue);
            }
        }

        /*
        * 以上的2个配置 CookieName, AesKey 可以自己从别的地方读取配置.
        */


        /// <summary>
        /// 获取票据
        /// </summary>
        /// <typeparam name="T">用户附加数据类型</typeparam>
        /// <param name="request">HttpRequest</param>
        /// <returns>登陆时设置的票据</returns>
        public AuthTicket<T> GetTicket<T>(HttpRequest request)
        {
            var cookie = request.Cookies[this.CookieName];
            if (cookie == null) return null;
            var cipherText = cookie.Value;
            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainText = "";
            try
            {
                plainText = SecurityUtils.AesDecrypt(cipherBytes, this.AesKey);
            }
            catch { return null; }
            if (String.IsNullOrWhiteSpace(plainText)) return null;
            return plainText.ParseJson<AuthTicket<T>>();
        }

        /// <summary>
        /// 设置登录时设置的票据并返回
        /// </summary>
        /// <param name="response">Http响应</param>
        /// <param name="uid">用户标识</param>
        /// <param name="roles">用户拥有的角色</param>
        /// <param name="days">有效时间</param>
        /// <param name="userData">用户附加数据(不需要可以设置成null)</param>
        /// <returns>认证票据</returns>
        public Tuple<string, string> SignIn(HttpResponse response, string uid, int days, string[] roles, object userData)
        {
            //在这里, 将用户标识(Uid), 用户角色(Roles)和盐值拼接成字符串
            //解密的时候也要按照这个格式来拆分获取
            var plainText = AuthTicket<object>.Create(uid, roles, userData).ToJson();
            var cipherBytes = SecurityUtils.AesEncrypt(plainText, AesKey);
            var cipherText = Convert.ToBase64String(cipherBytes);

            var cookie = new HttpCookie(this.CookieName);
            cookie.Value = cipherText;
            cookie.HttpOnly = true;
            cookie.Expires = DateTime.Now.AddDays(days);

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
            var items = this.GetTicket<object>(request);
            if (items == null) return null;
            return items.UserId;
        }


        /// <summary>
        /// 获取用户附加数据
        /// </summary>
        /// <typeparam name="T">用户附加数据类型</typeparam>
        /// <param name="request">Http请求</param>
        /// <returns>用户附加数据</returns>
        public T GetUserData<T>(HttpRequest request) where T : class
        {
            var items = this.GetTicket<T>(request);
            if (items == null) return null;
            return items.Data;
        }

        /// <summary>
        /// 退出登录
        /// </summary>
        /// <param name="response">HttpResponse</param>
        public void SignOut(HttpResponse response)
        {
            var cookie = new HttpCookie(this.CookieName);
            cookie.Expires = DateTime.Now.AddMinutes(-1);
            response.SetCookie(cookie);
        }

        /// <summary>
        /// 用户是否已认证
        /// </summary>
        /// <param name="request">Http请求</param>
        /// <returns>是否已认证</returns
        public bool IsAuthenticated(HttpRequest request)
        {
            return !String.IsNullOrWhiteSpace(this.GetUid(request));
        }

        /// <summary>
        /// 用户是否拥有某个角色
        /// 根据具体需求可以不实现这个方法
        /// </summary>
        /// <param name="roleName">角色名称</param>
        /// <returns>返回是否拥有某个角色</returns>
        public bool IsInRole(HttpRequest request, string roleName)
        {
            var items = this.GetTicket<object>(request);
            if (items == null) return false;
            var roles = items.Roles;
            if (roles == null || roles.Length == 0) return false;
            return roles.Any(role => role.ToLower() == roleName.ToLower());
        }

    }

}
