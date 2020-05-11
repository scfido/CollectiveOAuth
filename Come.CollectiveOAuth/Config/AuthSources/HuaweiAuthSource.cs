using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 华为
     */
    public class HuaweiAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://oauth-login.cloud.huawei.com/oauth2/v2/authorize";
        }

        public string AccessToken()
        {
            return "https://oauth-login.cloud.huawei.com/oauth2/v2/token";
        }

        public string UserInfo()
        {
            return "https://api.vmall.com/rest.php";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://oauth.kujiale.com/oauth2/auth/token/refresh";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.KUJIALE.ToString();
        }
    }
}