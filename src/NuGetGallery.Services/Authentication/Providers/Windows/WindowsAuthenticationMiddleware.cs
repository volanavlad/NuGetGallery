// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using NuGetGallery.Infrastructure.Authentication;
using Owin;

namespace NuGetGallery.Authentication.Providers.Windows
{
	public class WindowsAuthenticationMiddleware : AuthenticationMiddleware<WindowsAuthenticationOptions>
	{
		private ILogger _logger;

		public WindowsAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WindowsAuthenticationOptions options)
			: base(next, options)
		{
			_logger = app.CreateLogger<ILogger>();
		}

		protected override AuthenticationHandler<WindowsAuthenticationOptions> CreateHandler()
		{
			return new WindowsAuthenticationHandler(
				_logger,
				DependencyResolver.Current.GetService<AuthenticationService>(),
				DependencyResolver.Current.GetService<ICredentialBuilder>());
		}
		public override async Task Invoke(IOwinContext context)
		{
			try
			{
				if (context.Request.Path.StartsWithSegments(new PathString("/users/account/authenticate/Windows")))
				{
					if (null == context.TryGetUserWindowsIdentity())
					{
						context.Response.StatusCode = 401;
						context.Response.Headers.Append("WWW-Authenticate", @"Negotiate");
						context.Response.Headers.Append("WWW-Authenticate", @"NTLM");
						return;
					}
				}

				if (!context.Request.Path.StartsWithSegments(new PathString("/WinAuth"))) // let see real windows auth at this url
					if (null != context.TryGetUserWindowsIdentity())
						HttpContext.Current.User = null; // new WindowsPrincipal(WindowsIdentity.GetAnonymous());

				await base.Invoke(context);
			}
			finally
			{
				context.ClearWindowsIdentity();
			}
		}
	}

}