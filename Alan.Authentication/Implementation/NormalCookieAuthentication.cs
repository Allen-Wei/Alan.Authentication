using System;
using System.Configuration;
using System.Web;
using System.Collections.Generic;
using System.Globalization;
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
                var keyValue = ConfigurationSettings.AppSettings["Authentication-AESKey"] ?? "0a2667792b5a9027";
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
        /// <param name="getHeader">获取头里面的值</param>
        /// <returns>登陆时设置的票据</returns>
        public AuthTicket<T> GetTicket<T>(Func<string, string> getHeader)
        {
            var cipherText = getHeader(this.CookieName);
            if (String.IsNullOrEmpty(cipherText)) { return null; }
            var cipherBytes = Convert.FromBase64String(cipherText);
            string plainText;
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
        /// <param name="uid">用户标识</param>
        /// <param name="roles">用户拥有的角色</param>
        /// <param name="days">有效时间</param>
        /// <param name="userData">用户附加数据(不需要可以设置成null)</param>
        /// <returns>认证票据</returns>
        public Dictionary<string, string> SignIn(string uid, int days, string[] roles, object userData)
        {
            //在这里, 将用户标识(Uid), 用户角色(Roles)和盐值拼接成字符串
            //解密的时候也要按照这个格式来拆分获取
            var expire = DateTime.Now.AddDays(days);
            var plainText = AuthTicket<object>.Create(uid, roles, userData, expire).ToJson();
            var cipherBytes = SecurityUtils.AesEncrypt(plainText, AesKey);
            var cipherText = Convert.ToBase64String(cipherBytes);

            var cookieValue = AuthUtils.CreateCookieValue(this.CookieName, cipherText, expire, "/");

            var headers = new Dictionary<string, string>
            {
                { "Set-Cookie", cookieValue }
            };
            return headers;
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
        public void SignIn(HttpResponse response, string uid, int days, string[] roles, object userData)
        {
            var headers = this.SignIn(uid, days, roles, userData);
            foreach (var header in headers)
            {
                response.Headers.Add(header.Key, header.Value);
            }
        }


        /// <summary>
        /// 获取用户标识
        /// </summary>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>用户标识</returns>
        public string GetUid(Func<string, string> getHeader)
        {
            var ticket = this.GetTicket<object>(getHeader);
            if (ticket == null) return null;
            return ticket.UserId;
        }


        /// <summary>
        /// 获取用户附加数据
        /// </summary>
        /// <typeparam name="T">用户附加数据类型</typeparam>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>用户附加数据</returns>
        public T GetUserData<T>(Func<string, string> getHeader) where T : class
        {
            var items = this.GetTicket<T>(getHeader);
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
        /// <param name="getHeader">Http请求</param>
        /// <returns>是否已认证</returns>
        public bool IsAuthenticated(Func<string, string> getHeader)
        {
            return !String.IsNullOrWhiteSpace(this.GetUid(getHeader));
        }

        /// <summary>
        /// 用户是否拥有某个角色
        /// 根据具体需求可以不实现这个方法
        /// </summary>
        /// <param name="getHeader">获取Header值</param>
        /// <param name="roleName">角色名称</param>
        /// <returns>返回是否拥有某个角色</returns>
        public bool IsInRole(Func<string, string> getHeader, string roleName)
        {
            var items = this.GetTicket<object>(getHeader);
            if (items == null) return false;
            var roles = items.Roles;
            if (roles == null || roles.Length == 0) return false;
            return roles.Any(role => role.ToLower() == roleName.ToLower());
        }

    }

}
