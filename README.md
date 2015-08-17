# Alan.Authentication
Alan Authentication Module

nuget.org address: https://www.nuget.org/packages/Alan.Authentication/

## Step 1 Install
	
	Install-Package Alan.Authentication 

## Step 2 Configure

##### Step 2.1 向 web.config 中新增 HttpModule

	<system.webServer>
		<modules>
			<add name="AlanAuth" type="Alan.Authentication.AuthModule"/>
		</modules>
	</system.webServer>

##### Step 2.2 现在 Alan.Authentication 中已经有两个实现了, 一个是基于FormaAuthentication 的实现, 一个是AES加密生成Cookie的实现. 你也可以自己实现 `Alan.Authentication.Core.IAuthentication` 接口来满足自己的需求, 比如你可能把票据信息放在自定义的 Http Header里, 或者你的用户角色判断要从其他地方获取等等. 自己实现了那个接口之后在Global.asax.cs的 `Application_Start` 方法里注入自己的实现:
	
	Alan.Authentication.AuthUtils.InjectAuth(....);

比如我要使用 `Alan.Authentication.Implementation.NormalCookieAuthentication` 这个实现: 

	Alan.Authentication.AuthUtils.InjectAuth(new Alan.Authentication.Implementation.NormalCookieAuthentication());

一般情况下默认的那两个实现就满足了, 所以这一步可以不用执行.

## Step 3 Use

##### Step 3.1 登陆 Alan.Authentication.AuthUtils.Current.SignIn
##### Step 3.2 退出登录 Alan.Authentication.AuthUtils.Current.SignOut

如果不需要角色控制或者不需要附加数据, 登陆时的roles和data参数可以设置为null.
你可以下载源码, 运行Demo里的HomeController了解更多关于角色和用户数据的信息.
