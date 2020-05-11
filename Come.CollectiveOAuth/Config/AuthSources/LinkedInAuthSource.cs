using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Linkin领英
     */
    public class LinkedInAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://www.linkedin.com/oauth/v2/authorization";
        }

        public string AccessToken()
        {
            return "https://www.linkedin.com/oauth/v2/accessToken";
        }

        public string UserInfo()
        {
            return "https://api.linkedin.com/v2/me";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://www.linkedin.com/oauth/v2/accessToken";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.LINKEDIN.ToString();
        }
    }
}