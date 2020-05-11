using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Github
     */
    public class GithubAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://github.com/login/oauth/authorize";
        }

        public string AccessToken()
        {
            return "https://github.com/login/oauth/access_token";
        }

        public string UserInfo()
        {
            return "https://api.github.com/user";
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
            return DefaultAuthSourceEnum.GITHUB.ToString();
        }
    }
}