using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Gitlab
     */
    public class GitlabAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://gitlab.com/oauth/authorize";
        }

        public string AccessToken()
        {
            return "https://gitlab.com/oauth/token";
        }

        public string UserInfo()
        {
            return "https://gitlab.com/api/v4/user";
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
            return DefaultAuthSourceEnum.GITLAB.ToString();
        }
    }
}