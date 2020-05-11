using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 酷家乐
     */
    public class KujialeAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://oauth.kujiale.com/oauth2/show";
        }

        public string AccessToken()
        {
            return "https://oauth.kujiale.com/oauth2/auth/token";
        }

        public string UserInfo()
        {
            return "https://oauth.kujiale.com/oauth2/openapi/user";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://oauth-login.cloud.huawei.com/oauth2/v2/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.KUJIALE.ToString();
        }
    }
}