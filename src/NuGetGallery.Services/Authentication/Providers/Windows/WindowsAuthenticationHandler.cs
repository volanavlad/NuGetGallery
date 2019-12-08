// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using NuGetGallery.Infrastructure.Authentication;

namespace NuGetGallery.Authentication.Providers.Windows
{
	public class WindowsAuthenticationHandler : AuthenticationHandler<WindowsAuthenticationOptions>
	{
		private WindowsAuthenticationOptions _options;

		protected ILogger Logger { get; set; }
		protected AuthenticationService Auth { get; set; }
		protected ICredentialBuilder CredentialBuilder { get; set; }

		private WindowsAuthenticationOptions TheOptions { get { return _options ?? Options; } }

		public WindowsAuthenticationHandler(ILogger logger, AuthenticationService auth, ICredentialBuilder credentialBuilder)
		{
			Logger = logger ?? throw new ArgumentNullException(nameof(logger));
			Auth = auth ?? throw new ArgumentNullException(nameof(auth));
			CredentialBuilder = credentialBuilder ?? throw new ArgumentNullException(nameof(credentialBuilder));
		}

		internal Task InitializeAsync(WindowsAuthenticationOptions options, IOwinContext context)
		{
			_options = options; // Override the Options property
			return BaseInitializeAsync(options, context);
		}
		protected override Task ApplyResponseGrantAsync()
		{
			return base.ApplyResponseGrantAsync();
		}
		protected override Task InitializeCoreAsync()
		{
			return base.InitializeCoreAsync();
		}
		public override async Task<bool> InvokeAsync()
		{
			return await base.InvokeAsync();
		}
		protected override async Task TeardownCoreAsync()
		{
			await base.TeardownCoreAsync();
		}
		protected override async Task ApplyResponseChallengeAsync()
		{
			await base.ApplyResponseChallengeAsync();
		}

		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			var winIdentity = this.Context.TryGetUserWindowsIdentity();
			if (null == winIdentity)
				return null;
			if (!this.Context.Request.Path.StartsWithSegments(new PathString("/users/account/authenticate")))
				return null;

			var cid = winIdentity.GetClaimsIdentity();

			var ap = new AuthenticationProperties()
			{
				AllowRefresh = true,
				IsPersistent = true
			};
			//System.Web.HttpContext.Current.User = new ClaimsPrincipal(cid);
			return new AuthenticationTicket(cid, ap);
		}
	}
}