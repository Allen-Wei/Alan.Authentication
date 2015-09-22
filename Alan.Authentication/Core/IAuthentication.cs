using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Alan.Authentication.Core
{
    /// <summary>
    /// IAuthentication接口
    /// </summary>
    public interface IAuthentication
    {

        /// <summary>
        /// 返回设置登录时的票据
        /// </summary>
        /// <param name="uid">用户标识</param>
        /// <param name="roles">用户拥有的角色</param>
        /// <param name="days">有效时间</param>
        /// <param name="userData">用户附加数据(不需要可以设置成null)</param>
        /// <returns>认证票据</returns>
        Dictionary<string, string> SignIn(string uid, int days, string[] roles, object userData);

        /// <summary>
        /// 设置登录时设置的票据并返回
        /// </summary>
        /// <param name="response">HttpResponse</param>
        /// <param name="uid">用户标识</param>
        /// <param name="roles">用户拥有的角色</param>
        /// <param name="days">有效时间</param>
        /// <param name="userData">用户附加数据(不需要可以设置成null)</param>
        /// <returns>认证票据</returns>
        void SignIn(HttpResponse response, string uid, int days, string[] roles, object userData);

        /// <summary>
        /// 获取用户标识
        /// </summary>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>用户标识</returns>
        string GetUid(Func<string, string> getHeader);

        /// <summary>
        /// 获取用户附加数据
        /// </summary>
        /// <typeparam name="T">用户附加数据类型</typeparam>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>用户附加数据</returns>
        T GetUserData<T>(Func<string, string> getHeader) where T : class;

        /// <summary>
        /// 退出登录
        /// </summary>
        /// <param name="response">HttpResponse</param>
        void SignOut(HttpResponse response);

        /// <summary>
        /// 用户是否已认证
        /// </summary>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>是否已认证</returns>
        bool IsAuthenticated(Func<string, string> getHeader);

        /// <summary>
        /// 用户是否拥有某个角色
        /// 根据具体需求可以不实现这个方法
        /// </summary>
        /// <param name="getHeader">获取Header值</param>
        /// <param name="roleName">角色名称</param>
        /// <returns>返回是否拥有某个角色</returns>
        bool IsInRole(Func<string, string> getHeader, string roleName);

        /// <summary>
        /// 获取票据
        /// </summary>
        /// <typeparam name="T">用户附加数据类型</typeparam>
        /// <param name="getHeader">获取Header值</param>
        /// <returns>登陆时设置的票据</returns>
        AuthTicket<T> GetTicket<T>(Func<string, string> getHeader);
    }

}
