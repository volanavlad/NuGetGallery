// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using NuGetGallery.Authentication.Providers.ApiKey;

namespace NuGetGallery.Authentication.Providers.Windows
{
	/*
	 * var options = new CookieAuthenticationOptions
            {
                AuthenticationType = AuthenticationTypes.LocalUser,
                AuthenticationMode = AuthenticationMode.Active,
                CookieHttpOnly = true,
                CookieSecure = cookieSecurity,
                LoginPath = new PathString("/users/account/LogOn"),
                ExpireTimeSpan = TimeSpan.FromHours(6),
                SlidingExpiration = true
            };
	 * */
	public class WindowsAuthenticationOptions
	: AuthenticationOptions
	//: CookieAuthenticationOptions
	{
		public WindowsAuthenticationOptions()
			:base(AuthenticationTypes.External)
		{
			this.AuthenticationType = AuthenticationTypes.External;
			this.AuthenticationMode = AuthenticationMode.Active;

			//this.CookieHttpOnly = true;
			//this.CookieSecure = CookieSecureOption.Always;
			//this.LoginPath = new PathString("/users/account/authenticate/Windows");
			//this.ExpireTimeSpan = TimeSpan.FromHours(6);
			//this.SlidingExpiration = true;
			//this.CookieName = "WinUser";

		}
	}
}