using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Alan.Authentication;
using Alan.Authentication.Demo.Models;

namespace Alan.Authentication.Demo.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult SignIn()
        {
            return View();
        }
        /// <summary>
        /// 登陆
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [HttpPost]
        public ActionResult SignIn(Person p)
        {
            var uid = Request["userid"];
            var roles = (Request["roles"] ?? "").Split(' ');
            Alan.Authentication.AuthUtils.Current.SignIn(System.Web.HttpContext.Current.Response,
                "",
                7,
                roles,
                p);
            return View(p);
        }

        /// <summary>
        /// 当前登录用户信息
        /// </summary>
        /// <returns></returns>
        public ActionResult Current()
        {
            var ticket = AuthUtils.Current.GetTicket<Person>(name =>
            {
                var cookie = System.Web.HttpContext.Current.Request.Cookies[name] ?? new HttpCookie("");
                return cookie.Value;

            }) ?? new Core.AuthTicket<Person>();
            return View(ticket);
        }

        /// <summary>
        /// 退出登录
        /// </summary>
        /// <returns></returns>
        public ActionResult SignOut()
        {
            AuthUtils.Current.SignOut(System.Web.HttpContext.Current.Response);
            return View();
        }

        /// <summary>
        /// 必须认证(登陆)才能访问
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public ActionResult MustSignIn()
        {
            return View();
        }

        /// <summary>
        /// 必须拥有角色dev的认证用户才能访问
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "dev")]
        public ActionResult MustSpecialRole()
        {
            return View();
        }
    }
}