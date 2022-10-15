using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Contoso.API.Authorization
{
    public class CanGetWeatherPolicyProvider : IAuthorizationPolicyProvider
    {
        public const string POLICY_PREFIX = "CanGetWeather";
        public DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }
        public CanGetWeatherPolicyProvider(IOptions<AuthorizationOptions> options)
        {
            // ASP.NET Core only uses one authorization policy provider, so if the custom implementation
            // doesn't handle all policies (including default policies, etc.) it should fall back to an
            // alternate provider.
            //
            // In this sample, a default authorization policy provider (constructed with options from the 
            // dependency injection container) is used if this custom provider isn't able to handle a given
            // policy name.
            //
            // If a custom policy provider is able to handle all expected policy names then, of course, this
            // fallback pattern is unnecessary.
            FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith(POLICY_PREFIX, StringComparison.OrdinalIgnoreCase))
            {
                var policy = new AuthorizationPolicyBuilder();
                policy.AddRequirements(new CanGetWeatherRequirement());
                return Task.FromResult(policy.Build());
            }
            // If the policy name doesn't match the format expected by this policy provider,
            // try the fallback provider. If no fallback provider is used, this would return 
            // Task.FromResult<AuthorizationPolicy>(null) instead.
            return FallbackPolicyProvider.GetPolicyAsync(policyName);
        }
    }
}
