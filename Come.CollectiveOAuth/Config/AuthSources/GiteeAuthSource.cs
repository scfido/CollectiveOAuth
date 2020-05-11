using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Gitee
     */
    public class GiteeAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://gitee.com/oauth/authorize";
        }

        public string AccessToken()
        {
            return "https://gitee.com/oauth/token";
        }

        public string UserInfo()
        {
            return "https://gitee.com/api/v5/user";
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
            return DefaultAuthSourceEnum.GITEE.ToString();
        }
    }
}