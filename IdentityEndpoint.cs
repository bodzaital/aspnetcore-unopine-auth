namespace Unopine.Auth;

public enum IdentityEndpoint
{
	/// <summary>Endpoint configuration for registering,
	/// default: /register</summary>
	Register,

	/// <summary>Endpoint configuration for logging in,
	/// default: /login</summary>
	Login,

	/// <summary>Endpoint configuration for logging out,
	/// default: /logout</summary>
	Logout,

	/// <summary>Endpoint configuration for setting up 2FA,
	/// default: /2fa/setup</summary>
	Setup2FA,

	/// <summary>Endpoint configuration for enabling 2FA,
	/// default: /2fa/enable</summary>
	Enable2FA,

	/// <summary>Endpoint configuration for resetting recovery codes,
	/// default: /2fa/reset</summary>
	Reset2FA,

	/// <summary>Endpoint configuration for clearing "remember this browser" flag,
	/// default: /2fa/forget</summary>
	Forget2FA,

	/// <summary>Endpoint configuration for disabling 2FA,
	/// default: /2fa/disable</summary>
	Disable2FA,
}