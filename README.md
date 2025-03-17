# aspnetcore-unopine-auth
Slightly less opinionated copy ASP.NET Core Identity endpoints with Cookie-based authentication.

## Download

1. Clone the repository into your solution folder
2. Add the project to your solution
3. Add project reference in your consumer project

Download with terminal

With your solution folder as working directory, change PROJECT_FOLDER to your consumer project and run the following commands.

**Linux, macOS**

```sh
git clone https://github.com/bodzaital/aspnetcore-unopine-auth.git &&
mv aspnetcore-unopine-auth Unopine.Auth &&
dotnet sln add Unopine.Auth &&
dotnet add PROJECT_FOLDER reference Unopine.Auth
```

## Usage

In `Program.cs`, below the call to `MapControllers` add a call to `MapUnverifiedIdentityEndpoints` with an implementation of `IdentityUser`.

```c#
app.MapControllers();
app.MapUnverifiedIdentityEndpoints<IdentityUser>();
app.Run();
```

### Configuration

Unlike the default Identity endpoints, this supports some configuration. `MapUnverifiedIdentityEndpoints` has two optional parameters:

- `string? prefix = null`
- `Dictionary<IdentityEndpoint, string>?` endpointMap = null

The `prefix` parameter applies a prefix through a call to `IEndpointRouteBuilder.MapGroup`. For example, if you want to have all Identity endpoints on URLs like `/api/auth/login`, `/api/auth/register` etc. then add a prefix parameter of `"api/auth"`.

The `endpointMap parameter applies different endpoint routes than the default. For example, instead of "/login" you want to have "/signin" as the route for the logging in endpoint, add a new dictionary with only this entry.

```c#
new Dictionary<IdentityEndpoint, string>()
{
	{ IdentityEndpoint.Login, "signin" }
};
```

Any missing `IdentityEndpoint` keys will not be overridden.

### Full example

```c#
app.MapUnverifiedIdentityEndpoints<User>("api/identity", new()
{
    { IdentityEndpoint.Login, "signin" },
    { IdentityEndpoint.Logout, "signout" },
});
```

Creates the following endpoints:

```
POST /api/identity/register
POST /api/identity/signin (original: /api/identity/login)
POST /api/identity/signout (original: /api/identity/logout)
POST /api/identity/2fa/setup
POST /api/identity/2fa/enable
POST /api/identity/2fa/reset
POST /api/identity/2fa/forget
POST /api/identity/2fa/disable
```