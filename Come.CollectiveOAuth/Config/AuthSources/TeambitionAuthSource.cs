using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Teambition
     */
    public class TeambitionAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://account.teambition.com/oauth2/authorize";
        }

        public string AccessToken()
        {
            return "https://account.teambition.com/oauth2/access_token";
        }

        public string UserInfo()
        {
            return "https://api.teambition.com/users/me";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://account.teambition.com/oauth2/refresh_token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.TEAMBITION.ToString();
        }
    }
}