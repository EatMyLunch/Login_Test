using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace Login_Test.Helper
{
    public class AdAuthenticationService
    {
        private const string DomainPrefix = "INFINEON\\";

        public string FormatUsername(string username)
        {
            if (!username.StartsWith(DomainPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return DomainPrefix + username;
            }
            return username;
        }

        public bool AuthenticateUser(string username, string password)
        {
            try
            {
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "INFINEON"))
                {
                    return pc.ValidateCredentials(username, password);
                }
            }
            catch
            {
                return false;
            }
        }

        public UserPrincipal GetUserPrincipal(string username)
        {
            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "INFINEON"))
            {
                return UserPrincipal.FindByIdentity(pc, username);
            }
        }

        public string GetUserMail(UserPrincipal user)
        {
            return user.GetUnderlyingObject() is DirectoryEntry de ? de.Properties["mail"].Value?.ToString() : null;
        }

        public string GetUserDepartment(UserPrincipal user)
        {
            return user.GetUnderlyingObject() is DirectoryEntry de ? de.Properties["department"].Value?.ToString() : null;
        }
    }

}
