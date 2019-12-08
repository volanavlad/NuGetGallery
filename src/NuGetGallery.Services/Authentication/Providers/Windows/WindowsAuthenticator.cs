// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NuGetGallery.Authentication.Providers.Cookie;
using NuGetGallery.Configuration;
using NuGetGallery.Infrastructure.Authentication;
using Owin;

namespace NuGetGallery.Authentication.Providers.Windows
{
	public class WindowsAuthenticator : Authenticator
	{
		public static readonly string DefaultAuthenticationType = "Windows";
		public static readonly string ClaimTypeName = "name";
		bool isAttached;
		protected override void AttachToOwinApp(IGalleryConfigurationService config, IAppBuilder app)
		{
			if (isAttached)
				return;

			isAttached = true;
			var options = new WindowsAuthenticationOptions();
			
			BaseConfig.ApplyToOwinSecurityOptions(options);
			//app.UseCookieAuthentication(options);

			app.Use(typeof(WindowsAuthenticationMiddleware), app, options);
			app.UseStageMarker(PipelineStage.Authenticate);
			
		}

		private void PrintCurrentIntegratedPipelineStage(IOwinContext context, string msg)
		{
			var currentIntegratedpipelineStage = HttpContext.Current.CurrentNotification;
			context.Get<TextWriter>("host.TraceOutput").WriteLine(
				"Current IIS event: " + currentIntegratedpipelineStage
															+ " Msg: " + msg);
		}
		public override bool IsProviderForIdentity(ClaimsIdentity claimsIdentity)
		{
			// If the issuer of the claims identity is same as that of the authentication type then this is the author.
			var firstClaim = claimsIdentity?.Claims?.FirstOrDefault(c => c.Type == "WindowsAccount");
			if (firstClaim == null)
			{
				return base.IsProviderForIdentity(claimsIdentity);
			}

			return true;
		}
		public override ActionResult Challenge(string redirectUrl, AuthenticationPolicy policy)
		{
			var context = HttpContext.Current.GetOwinContext();
			if (context.Request.Path.StartsWithSegments(new PathString("/users/account/authenticate/Windows")))
			{
				if (null == context.TryGetUserWindowsIdentity())
				{
					//context.Response.StatusCode = 401;
					//context.Response.Headers.Append("WWW-Authenticate", @"Negotiate");
					//context.Response.Headers.Append("WWW-Authenticate", @"NTLM");
					return base.Challenge(redirectUrl,policy);
				}
			}

			return new RedirectResult(redirectUrl); 
		}


		protected internal override AuthenticatorConfiguration CreateConfigObject()
		{
			return new AuthenticatorConfiguration
			{
				AuthenticationType = AuthenticationTypes.External,
				Enabled = true
			};
		}
		public override IdentityInformation GetIdentityInformation(ClaimsIdentity claimsIdentity)
		{
			return claimsIdentity.GetWindowsAccountIdentityInformation();
		}
		public override AuthenticatorUI GetUI()
		{
			return new AuthenticatorUI(
				"Sign with Windows ActiveDirectory",
				"Register with Windows ActiveDirectory",
				"Windows ActiveDirectory Account")
			{
				IconImagePath = "~/Content/gallery/img/microsoft-account.svg",
				IconImageFallbackPath = "~/Content/gallery/img/microsoft-account-24x24.png",

				ShowOnLoginPage = true
			};

		}

	}
}