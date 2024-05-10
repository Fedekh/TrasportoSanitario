using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using TrasportoSanitario.Data;

namespace TrasportoSanitario.Services
{
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(
           IUserStore<ApplicationUser> store,
           IOptions<IdentityOptions> optionsAccessor,
           IPasswordHasher<ApplicationUser> passwordHasher,
           IEnumerable<IUserValidator<ApplicationUser>> userValidators,
           IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators,
           ILookupNormalizer keyNormalizer,
           IdentityErrorDescriber errors,
           IServiceProvider services,
           ILogger<UserManager<ApplicationUser>> logger)
           : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override async Task<IdentityResult> CreateAsync(ApplicationUser user, string password)
        {
            var result = await base.CreateAsync(user, password);
            if (result.Succeeded)
            {
                // Ottieni il ruolo "user" dallo store dei ruoli
                var role = await this.FindByNameAsync("user");
                if (role != null)
                {
                    // Assegna il ruolo all'utente
                    await this.AddToRoleAsync(user, role.Name);
                }
            }
            return result;
        }
    }
}
