﻿using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using SecurityLearning.Client.Models;
using System.Collections.Generic;
using System.Diagnostics;
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
            var expiresAt = await HttpContext.GetTokenAsync("expires_at");

            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

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
