using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using SecurityLearning.Client.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace SecurityLearning.Client.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public async Task<IActionResult> Index()
        {
            await WriteOutIdentityInformation();
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize(Roles = "PayingUser")]
        public IActionResult OnlyForPayingUser()
        {
            return View();
        }

        public async Task Logout()
        {
            //Clear the local cookie ("Cookies" is the name of scheme)
            await HttpContext.SignOutAsync("Cookies");

            //Clear the identity cookie
            await HttpContext.SignOutAsync("oidc");
        }

        public async Task<IEnumerable<string>> GetValuesInApi()
        {
            var accessToken = string.Empty;

            var expiresAt = await HttpContext.GetTokenAsync("expires_at");

            if (string.IsNullOrWhiteSpace(expiresAt)
                || ((DateTime.Parse(expiresAt).AddSeconds(-60)).ToUniversalTime() < DateTime.UtcNow))
            {
                accessToken = await RenewTokens();
            }
            else
            {
                accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }

            using (var httpClient = new HttpClient())
            {
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.SetBearerToken(accessToken);
                }

                var response = await httpClient.GetAsync("https://localhost:44369/api/values");
                var responseBody = await response.Content.ReadAsStringAsync();
                var values = JsonConvert.DeserializeObject<IEnumerable<string>>(responseBody);

                return values;
            };
        }

        public async Task<string> GetAddress()
        {
            var discoveryClient = new DiscoveryClient("https://localhost:44359/");
            var metaDataResponse = await discoveryClient.GetAsync();

            var userInfoClient = new UserInfoClient(metaDataResponse.UserInfoEndpoint);

            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            var response = await userInfoClient.GetAsync(accessToken);

            if (response.IsError)
            {
                throw response.Exception;
            }

            var address = response.Claims.FirstOrDefault(c => c.Type == "address")?.Value;

            return address;
        }

        [Authorize(Policy = "CanGetCountries")]
        public IEnumerable<string> GetCountries()
        {
            return new List<string> { "br", "usa", "af" };
        }

        private async Task<string> RenewTokens()
        {
            // get the metadata
            var discoveryClient = new DiscoveryClient("https://localhost:44359/");
            var metaDataResponse = await discoveryClient.GetAsync();

            // create a new token client to get new tokens
            var tokenClient = new TokenClient(metaDataResponse.TokenEndpoint,
                "imagegalleryclient", "secret");

            // get the saved refresh token
            var currentRefreshToken = await HttpContext
                .GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

            // refresh the tokens
            var tokenResult = await tokenClient.RequestRefreshTokenAsync(currentRefreshToken);

            if (!tokenResult.IsError)
            {
                // update the tokens & exipration value
                var updatedTokens = new List<AuthenticationToken>();
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = tokenResult.IdentityToken
                });
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.AccessToken,
                    Value = tokenResult.AccessToken
                });
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.RefreshToken,
                    Value = tokenResult.RefreshToken
                });

                var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(tokenResult.ExpiresIn);
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = "expires_at",
                    Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                });

                // get authenticate result, containing the current principal & 
                // properties
                var currentAuthenticateResult = await HttpContext.AuthenticateAsync("Cookies");

                // store the updated tokens
                currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

                // sign in
                await HttpContext.SignInAsync("Cookies",
                    currentAuthenticateResult.Principal,
                    currentAuthenticateResult.Properties);

                // return the new access token 
                return tokenResult.AccessToken;
            }
            else
            {

                throw new Exception("Problem encountered while refreshing tokens.",
                    tokenResult.Exception);
            }
        }

        public async Task WriteOutIdentityInformation()
        {
            // get the saved identity token
            var identityToken = await HttpContext
                .GetTokenAsync(OpenIdConnectParameterNames.IdToken);

            // write it out
            Debug.WriteLine($"Identity token: {identityToken}");

            // write out the user claims
            foreach (var claim in User.Claims)
            {
                Debug.WriteLine($"Claim type: {claim.Type} - Claim value: {claim.Value}");
            }
        }
    }
}
