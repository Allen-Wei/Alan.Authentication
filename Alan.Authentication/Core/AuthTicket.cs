using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Alan.Authentication.Core
{
    /// <summary>
    /// 认证票据
    /// </summary>
    /// <typeparam name="T">用户数据类型</typeparam>
    public class AuthTicket<T>
    {
        /// <summary>
        /// 用户标识
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// 用户角色
        /// </summary>
        public string[] Roles { get; set; }

        /// <summary>
        /// 用户数据
        /// </summary>
        public T Data { get; set; }

        public static AuthTicket<T> Create(string uid, string[] roles, T data)
        {
            return new AuthTicket<T>()
            {
                UserId = uid,
                Roles = roles,
                Data = data
            };
        }
    }
}
