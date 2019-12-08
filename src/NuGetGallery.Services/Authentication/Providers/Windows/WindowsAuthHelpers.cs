// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace NuGetGallery.Authentication.Providers.Windows
{

	public static class WindowsAuthHelpers
	{
		private const string WinAuthId = "WinAuthIdentity";
		public static ClaimsIdentity GetClaimsIdentity(this WindowsIdentity winIdentity)
		{
			var userId = winIdentity.GetUserId();

			var claims = new List<Claim>()
			{
				new Claim("WindowsAccount", winIdentity.Name)
			, new Claim(ClaimTypes.Name, userId)
			, new Claim(ClaimTypes.Email, userId.GetEMail())
			, new Claim(ClaimTypes.NameIdentifier, userId)
			};

			var cid = new ClaimsIdentity(claims, authenticationType: AuthenticationTypes.External);
			return cid;
		}
		static string GetUserId(this WindowsIdentity winId)
		{
			return winId.Name.GetUserId();
		}
		static string GetUserId(this string winId)
		{
			return winId.Replace('\\', '_');
		}
		static string GetEMail(this string userId)
		{
			return userId + "@gmail.com";
		}
		public static IdentityInformation GetWindowsAccountIdentityInformation(this ClaimsIdentity claimsIdentity)
		{
			var firstClaim = claimsIdentity?.Claims?.FirstOrDefault(c => c.Type == "WindowsAccount");
			if (firstClaim == null)
			{
				return null;
			}
			var id = firstClaim.Value;
			var name = id.GetUserId();
			var ii = new IdentityInformation(name, name, name.GetEMail(), "Windows");
			return ii;
		}
		public static void ClearWindowsIdentity(this IOwinContext context)
		{
			if (context.Environment.ContainsKey(WinAuthId))
				context.Environment.Remove(WinAuthId);
		}
		public static WindowsIdentity TryGetUserWindowsIdentity(this IOwinContext context)
		{
			WindowsIdentity windowsIdentity=null;

			if (context.Environment.TryGetValue(WinAuthId, out var winIdObj))
			{
				windowsIdentity = winIdObj as WindowsIdentity;
			}
			else
			{
				if (!(HttpContext.Current?.User is WindowsPrincipal windowsPrincipal))
					return null;

				windowsIdentity = windowsPrincipal.Identity as WindowsIdentity;
			}
			if (windowsIdentity == null)
				return null;

			if (!windowsIdentity.IsAuthenticated)
				return null;

			context.Environment[WinAuthId] = windowsIdentity;
			return windowsIdentity;
		}
	}
}