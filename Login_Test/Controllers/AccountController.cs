using Login_Test.Helper;
using Login_Test.Viewmodels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.DirectoryServices.AccountManagement;

namespace Login_Test.Controllers
{
    public class AccountController : Controller
    {
        private readonly AdAuthenticationService _authService;

        public AccountController(AdAuthenticationService authService)
        {
            _authService = authService;
        }

        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                return View(model);
            }
            var formattedUsername = _authService.FormatUsername(model.Username);
            var isValidUser = _authService.AuthenticateUser(formattedUsername, model.Password);
            if (!isValidUser)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                ViewData["ReturnUrl"] = returnUrl;
                return View(model);
            }
            await SignInUser(formattedUsername);
            return RedirectToLocal(returnUrl);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AutoLogin(string returnUrl = null)
        {
            if (User.Identity.IsAuthenticated)
            {
                await SignInUser(User.Identity.Name);
                return RedirectToLocal(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(Login), new { returnUrl });
            }
        }

        private async Task SignInUser(string username)
        {
            var userPrincipal = _authService.GetUserPrincipal(username);
            var claims = CreateClaims(userPrincipal, username);
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));
        }

        private List<Claim> CreateClaims(UserPrincipal userPrincipal, string username)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.Name, username),
                new Claim("Department", _authService.GetUserDepartment(userPrincipal) ?? ""),
                new Claim("Mail", _authService.GetUserMail(userPrincipal) ?? "")
            };
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}
