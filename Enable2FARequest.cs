namespace Unopine.Auth;

/// <summary>The request type for the "/2fa/enable" endpoint added by <see cref="UnverifiedIdentityEndpointsExtensions.MapUnverifiedIdentityEndpoints"/>.</summary>
/// <param name="TwoFactorCode">The two-factor code derived from the shared key, returned by the "/2fa/setup" endpoint.</param>
public record Enable2FARequest(string TwoFactorCode);