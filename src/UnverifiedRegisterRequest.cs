namespace Unopine.Auth;

/// <summary>The request type for the "/register" endpoint added by <see cref="UnverifiedIdentityEndpointsExtensions.MapUnverifiedIdentityEndpoints"/></summary>
/// <param name="Username">The user's name which acts as their identifier.</param>
/// <param name="Password">The user's password</param>
public record RegisterRequest(string Username, string Password);