namespace Unopine.Auth;

/// <summary>The request type for the "/login" endpoint added by <see cref="UnverifiedIdentityEndpointsExtensions.MapUnverifiedIdentityEndpoints"/>.</summary>
/// <param name="Username">The user's name which acts as their identifier.</param>
/// <param name="Password">The user's password.</param>
/// <param name="TwoFactorCode">The optional two-factor authenticator code. Required if two-factor login is enabled. Not required if <see cref="RecoveryCode"/> is sent.</param>
/// <param name="RecoveryCode">The optional two-factor recovery code. Required if two-factor login is enabled but lost access to <see cref="TwoFactorCode"/>. Not required if <see cref="TwoFactorCode"/> is sent.</param>
public record LoginRequest(string Username, string Password, string? TwoFactorCode, string? RecoveryCode);