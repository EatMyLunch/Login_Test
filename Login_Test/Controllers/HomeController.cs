using Login_Test.Helper;
using Login_Test.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace Login_Test.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [RequireLogin]
        public IActionResult Index()
        {
            ViewBag.UserName = User.Identity.Name;
            ViewBag.Mail = User.FindFirstValue("Mail");
            ViewBag.Department = User.FindFirstValue("Department");

            return View();
        }

        [RequireLogin]
        [HttpGet]
        public IActionResult GrabData(string search)
        {
            if (string.IsNullOrWhiteSpace(search) || search.Length < 2)
            {
                return Json(new { results = new List<object>() });
            }

            using (var context = new PrincipalContext(ContextType.Domain, "INFINEON"))
            {
                var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://INFINEON"))
                {
                    Filter = $"(&(objectCategory=person)(objectClass=user)(displayName=*{search}*))",
                    PropertiesToLoad = { "displayName", "samAccountName", "mail" }
                };

                var results = searcher.FindAll()
                    .Cast<SearchResult>()
                    .Where(result => result.Properties.Contains("mail") && result.Properties["mail"].Count > 0)
                    .Select(result => new
                    {
                        id = result.Properties["samAccountName"][0].ToString(),
                        displayName = result.Properties["displayName"][0].ToString()
                    })
                    .Distinct()
                    .Take(10)
                    .Select(user => new
                    {
                        id = user.id,
                        text = user.displayName
                    })
                    .ToList();

                return Json(new { results });
            }
        }

        [RequireLogin]
        [HttpPost]
        public IActionResult SubmitUser(string selectedUserId)
        {
            if (!string.IsNullOrEmpty(selectedUserId))
            {
                string windowsUsername = $"INFINEON\\{selectedUserId}";
                TempData["SelectedWindowsUsername"] = windowsUsername;
            }
            return RedirectToAction("Index");
        }

        public IActionResult About()
        {
            return View();
        }

        [RequireLogin]
        [Authorize(Policy = "Admin")]
        public IActionResult Admin()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
