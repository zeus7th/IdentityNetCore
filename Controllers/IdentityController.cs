using IdentityNetCore.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public IdentityController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            return View();
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignUpViewModel() { Role="Member"};
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Signup(SignUpViewModel model)
        {            
            if (ModelState.IsValid)
            {
                if (!await _roleManager.RoleExistsAsync(model.Role))
                {
                    var role = new IdentityRole { Name = model.Role };
                    var roleResult = await _roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(s => s.Description);
                        ModelState.AddModelError("Role", string.Join(",",errors) );
                        return View(model);
                    }
                }

                if (await _userManager.FindByEmailAsync(model.Email) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);                    

                    if (result.Succeeded)
                    {
                        user = await _userManager.FindByEmailAsync(model.Email);
                        var claim = new Claim("Department", model.Department);
                        await _userManager.AddClaimAsync(user, claim);
                        
                        await _userManager.AddToRoleAsync(user,model.Role);
                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var callbackurl = Url.Action("ConfirmEmail", "Identity", new
                        {
                            userId = user.Id,
                            @token = code,
                        },protocol:HttpContext.Request.Scheme);
                        /*
                        await _emailSender.SendEmailAsync(model.Email, "Confirm Email - Identity Manage",
                            $"Please, confirm your email by clicking here: <a href='{callbackurl}'>link</a>");
                        */
                        return RedirectToAction("Signin");
                    }
                    ModelState.AddModelError("Signin", string.Join("", result.Errors.Select(x=>x.Description)));
                    return View(model);
                    
                }
            }
            return View(model);
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl=null)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, returnUrl);
            var callBackUrl = Url.Action("ExternalLoginCallBack");
            properties.RedirectUri = callBackUrl;
            return Challenge(properties,provider);
        }

        public async Task<IActionResult> ExternalLoginCallBack()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            var emailClaim = info.Principal.Claims.FirstOrDefault(x=>x.Type==ClaimTypes.Email);
            var user = new IdentityUser { Email = emailClaim.Value, UserName = emailClaim.Value};
            await _userManager.CreateAsync(user);
            await _userManager.AddLoginAsync(user, info);
            await _signInManager.SignInAsync(user, false);

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> MFASetup()
        {
            const string provider = "aspnetidentity";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var QRCodeUrl = $"otpauth://totp/{provider}:{user.Email}?secret={token}&issuer={provider}&digits=6";
            var model = new MFAViewModel {Token = token, QRCodeUrl=QRCodeUrl};

            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFAViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync (User);
                var succeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

                if (succeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your MFA code could not be validated");
                }
            }
            return View(model);
        }

        public async Task<IActionResult>ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded) 
            {
                return RedirectToAction("Signin");
            }

            return new NotFoundResult();
        }

        [HttpGet]
        public IActionResult Signin()
        {            
            return View(new SigninViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult>Signin(SigninViewModel model)
        {
            if (ModelState.IsValid) 
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);

                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction("MFACheck");
                }

                if (result.Succeeded) 
                {
                    var user = await _userManager.FindByEmailAsync(model.Username);

                    var userClaims = await _userManager.GetClaimsAsync(user);
                    

                    if (await _userManager.IsInRoleAsync(user, "Member"))
                    {                            
                        return RedirectToAction("Member", "Home");                            
                    }                    
                    
                }
                else
                {
                    ModelState.AddModelError("Login", "Cannot login");
                }

            }
            return View(model);
        }

        [HttpGet]
        public IActionResult MFACheck()
        {
            return View(new MFACheckViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> MFACheck(MFACheckViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, false, false);
                if (result.Succeeded) return RedirectToAction("Index", "Home", null);
            }
            return View(model); 
        }


        public async Task<IActionResult> AccessDenied()
        {
            var model = new SignUpViewModel();
            return View(model);
        }

        public async Task<IActionResult> Signout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }
    }
}
