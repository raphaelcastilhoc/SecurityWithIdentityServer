using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityLearning.Client.Models;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SecurityLearning.Client.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
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

        public async Task Logout()
        {
            //Clear the local cookie ("Cookies" is the name of scheme)
            await HttpContext.SignOutAsync("Cookies");

            //Clear the identity cookie
            await HttpContext.SignOutAsync("oidc");
        }
    }
}
