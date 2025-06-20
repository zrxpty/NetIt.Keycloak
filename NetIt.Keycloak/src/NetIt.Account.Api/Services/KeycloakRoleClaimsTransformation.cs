using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace NetIt.Account.Api.Services;

public class KeycloakRoleClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is ClaimsIdentity identity)
        {
            // Проверяем, что роли еще не добавлены
            if (!identity.HasClaim(c => c.Type == ClaimTypes.Role))
            {
                // Ищем клейм с JSON resource_access
                var resourceAccessClaim = identity.FindFirst("resource_access");
                if (resourceAccessClaim != null)
                {
                    try
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(resourceAccessClaim.Value);
                        if (doc.RootElement.TryGetProperty("netit", out var netitElement) &&
                            netitElement.TryGetProperty("roles", out var rolesElement) &&
                            rolesElement.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var role in rolesElement.EnumerateArray())
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString() ?? ""));
                            }
                        }
                    }
                    catch
                    {
                        // Игнорируем ошибки парсинга
                    }
                }
            }
        }

        return Task.FromResult(principal);
    }
}