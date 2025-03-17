using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Unopine.Auth;

/// <summary>Provides extension methods for <see cref="IEndpointRouteBuilder"/> to add unverified (without email) and configurable identity endpoints.</summary>
public static class UnverifiedIdentityEndpointsExtensions
{
	/// <summary>Add configurable endpoints for registering, logging in, and logging out using ASP.NET Core Identity.</summary>
	/// <typeparam name="TUser">The type describing the user, derived from <see cref="IdentityUser"/>.</typeparam>
	/// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the identity endpoints to.</param>
	/// <param name="prefix">Prefix to all identity endpoints.</param>
	/// <param name="endpointMap">Optionally provide custom endpoints for <see cref="IdentityEndpoint"/>s.</param>
	/// <returns>An <see cref="IEndpointConventionBuilder"/> to further customize the added endpoints.</returns>
	public static IEndpointConventionBuilder MapUnverifiedIdentityEndpoints<TUser>(
		this IEndpointRouteBuilder endpoints,
		string? prefix = null,
		Dictionary<IdentityEndpoint, string>? endpointMap = null
	) where TUser : class, new()
	{
		prefix ??= string.Empty;
		endpointMap = DefaultIdentityEndpointMap(endpointMap);
		
		RouteGroupBuilder routeGroup = endpoints.MapGroup(prefix);

        routeGroup.MapPost(endpointMap[IdentityEndpoint.Register], Register<TUser>);
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Login], Login<TUser>);
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Logout], Logout<TUser>).RequireAuthorization();
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Setup2FA], Setup2FA<TUser>).RequireAuthorization();
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Enable2FA], Enable2FA<TUser>).RequireAuthorization();
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Reset2FA], Reset2FA<TUser>).RequireAuthorization();
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Forget2FA], Forget2FA<TUser>).RequireAuthorization();
		routeGroup.MapPost(endpointMap[IdentityEndpoint.Disable2FA], Disable2FA<TUser>).RequireAuthorization();

		return new IdentityEndpointsConventionBuilder(routeGroup);
	}

	private static async Task<Results<Ok, ValidationProblem>> Register<TUser>(
		[FromBody] RegisterRequest registration,
		HttpContext context,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		UserManager<TUser> userManager = services.GetRequiredService<UserManager<TUser>>();
		IUserStore<TUser> userStore = services.GetRequiredService<IUserStore<TUser>>();

		TUser user = new();
		await userStore.SetUserNameAsync(user, registration.Username, CancellationToken.None);

		IdentityResult? result = await userManager.CreateAsync(user, registration.Password);

		if (!result.Succeeded) return CreateValidationProblem(result);

		return TypedResults.Ok();
	}

	private static async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>> Login<TUser>(
		[FromBody] LoginRequest login,
		[FromQuery] bool? rememberMe,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();

		signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;

		SignInResult? result = await signInManager.PasswordSignInAsync(login.Username, login.Password, rememberMe ?? false, false);

		if (result.RequiresTwoFactor)
		{
			if (!string.IsNullOrEmpty(login.TwoFactorCode))
			{
				result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, rememberMe ?? false, rememberMe ?? false);
			}
			else if (!string.IsNullOrEmpty(login.RecoveryCode))
			{
				result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.RecoveryCode);
			}
		}

		if (!result.Succeeded)
		{
			return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
		}

		return TypedResults.Empty;
	}

	private static async Task<Results<Ok, UnauthorizedHttpResult>> Logout<TUser>(
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();

		await signInManager.SignOutAsync();
		return TypedResults.Ok();
	}

	private static async Task<Results<NoContent, NotFound>> Forget2FA<TUser>(
		ClaimsPrincipal principal,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();
		UserManager<TUser> userManager = signInManager.UserManager;

		if (await userManager.GetUserAsync(principal) is not { } user)
		{
			return TypedResults.NotFound();
		}

		await signInManager.ForgetTwoFactorClientAsync();

		return TypedResults.NoContent();
	}

	private static async Task<Results<Ok<string>, NotFound>> Setup2FA<TUser>(
		ClaimsPrincipal principal,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();
		UserManager<TUser> userManager = signInManager.UserManager;

		if (await userManager.GetUserAsync(principal) is not { } user)
		{
			return TypedResults.NotFound();
		}

		string key = await GetAuthenticatorKeyAsync(userManager, user);
		return TypedResults.Ok(key);
	}

	private static async Task<Results<Ok<Enable2FAResponse>, BadRequest, NotFound>> Enable2FA<TUser>(
		ClaimsPrincipal principal,
		[FromBody] Enable2FARequest tfa,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();
		UserManager<TUser> userManager = signInManager.UserManager;

		if (await userManager.GetUserAsync(principal) is not { } user)
		{
			return TypedResults.NotFound();
		}

		if (string.IsNullOrEmpty(tfa.TwoFactorCode)) return TypedResults.BadRequest();
		
		bool isVerified = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, tfa.TwoFactorCode);

		if (!isVerified) return TypedResults.BadRequest();

		await userManager.SetTwoFactorEnabledAsync(user, true);

		IEnumerable<string>? recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
		if (recoveryCodesEnumerable is null) return TypedResults.BadRequest();

		string[] recoveryCodes = [.. recoveryCodesEnumerable];
		return TypedResults.Ok(new Enable2FAResponse([.. recoveryCodesEnumerable], true));
	}

	private static async Task<Results<Ok<string[]>, BadRequest, NotFound>> Reset2FA<TUser>(
		ClaimsPrincipal principal,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();
		UserManager<TUser> userManager = signInManager.UserManager;

		if (await userManager.GetUserAsync(principal) is not { } user)
		{
			return TypedResults.NotFound();
		}

		IEnumerable<string>? recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
		if (recoveryCodesEnumerable is null) return TypedResults.BadRequest();

		string[] recoveryCodes = [.. recoveryCodesEnumerable];
		return TypedResults.Ok(recoveryCodes);
	}

	private static async Task<Results<NoContent, NotFound>> Disable2FA<TUser>(
		ClaimsPrincipal principal,
		[FromServices] IServiceProvider services
	) where TUser : class, new()
	{
		SignInManager<TUser> signInManager = services.GetRequiredService<SignInManager<TUser>>();
		UserManager<TUser> userManager = signInManager.UserManager;

		if (await userManager.GetUserAsync(principal) is not { } user)
		{
			return TypedResults.NotFound();
		}

		await userManager.ResetAuthenticatorKeyAsync(user);
		await userManager.SetTwoFactorEnabledAsync(user, false);

		return TypedResults.NoContent();
	}

	private static async Task<string> GetAuthenticatorKeyAsync<TUser>(
		UserManager<TUser> userManager,
		TUser user
	) where TUser : class, new()
	{
		string? key = await userManager.GetAuthenticatorKeyAsync(user);
		if (!string.IsNullOrEmpty(key)) return key;

		await userManager.ResetAuthenticatorKeyAsync(user);

		key = await userManager.GetAuthenticatorKeyAsync(user);
		if (!string.IsNullOrEmpty(key)) return key;

		throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
	}

	private static Dictionary<IdentityEndpoint, string> DefaultIdentityEndpointMap(Dictionary<IdentityEndpoint, string>? endpointMap)
	{
		Dictionary<IdentityEndpoint, string> defaultMap = new()
		{
			{ IdentityEndpoint.Register, "/register" },
			{ IdentityEndpoint.Login, "/login" },
			{ IdentityEndpoint.Logout, "/logout" },
			{ IdentityEndpoint.Setup2FA, "/2fa/setup" },
			{ IdentityEndpoint.Enable2FA, "/2fa/enable" },
			{ IdentityEndpoint.Reset2FA, "/2fa/reset" },
			{ IdentityEndpoint.Forget2FA, "/2fa/forget" },
			{ IdentityEndpoint.Disable2FA, "/2fa/disable" },
		};

		if (endpointMap is null) return defaultMap;

		foreach (IdentityEndpoint value in Enum.GetValues<IdentityEndpoint>())
		{
			if (!endpointMap.ContainsKey(value))
			{
				endpointMap.Add(value, defaultMap[value]);
			}
		}

		return endpointMap;
	}

	private static ValidationProblem CreateValidationProblem(IdentityResult result)
	{
		Dictionary<string, string[]> errors = new(1);

		foreach (IdentityError? error in result.Errors)
		{
			string[] newDescriptions;

			if (errors.TryGetValue(error.Code, out string[]? descriptions))
			{
				newDescriptions = new string[descriptions.Length + 1];
				Array.Copy(descriptions, newDescriptions, descriptions.Length);
				newDescriptions[descriptions.Length] = error.Description;
			}
			else
			{
				newDescriptions = [ error.Description ];
			}

			errors[error.Code] = newDescriptions;
		}

		return TypedResults.ValidationProblem(errors);
	}

	private sealed class IdentityEndpointsConventionBuilder(RouteGroupBuilder inner) : IEndpointConventionBuilder
	{
		private IEndpointConventionBuilder _innerAsConventionBuilder => inner;

		public void Add(Action<EndpointBuilder> convention) =>
			_innerAsConventionBuilder.Add(convention);

		public void Finally(Action<EndpointBuilder> finallyConvention) =>
			_innerAsConventionBuilder.Finally(finallyConvention);
	}

	[AttributeUsage(AttributeTargets.Parameter)]
	private sealed class FromBodyAttribute : Attribute, IFromBodyMetadata { }

	[AttributeUsage(AttributeTargets.Parameter)]
	private sealed class FromServicesAttribute : Attribute, IFromServiceMetadata { }

	[AttributeUsage(AttributeTargets.Parameter)]
	private sealed class FromQueryAttribute : Attribute, IFromQueryMetadata
	{
		public string? Name => null;
	}
}