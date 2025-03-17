namespace Unopine.Auth;

/// <summary>The response type for the "/2fa/enable" endpoint added by <see cref="UnverifiedIdentityEndpointsExtensions.MapUnverifiedIdentityEndpoints"/>.</summary>
/// <param name="RecoveryCodes">The recovery codes to use if the shared key is lost.</param>
/// <param name="IsTwoFactorEnabled">Confirms two-factor login is enabled and required for subsequent logins.</param>
public record Enable2FAResponse(string[] RecoveryCodes, bool IsTwoFactorEnabled);