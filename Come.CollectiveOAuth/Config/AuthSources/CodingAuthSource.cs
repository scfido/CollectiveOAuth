using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Coding扣钉
     */
    public class CodingAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://coding.net/oauth_authorize.html";
        }

        public string AccessToken()
        {
            return "https://coding.net/api/oauth/access_token";
        }

        public string UserInfo()
        {
            return "https://coding.net/api/account/current_user";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            throw new System.NotImplementedException();
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.CODING.ToString();
        }
    }
}