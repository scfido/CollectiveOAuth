using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 百度开放平台
     */
    public class BaiduAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://openapi.baidu.com/oauth/2.0/authorize";
        }

        public string AccessToken()
        {
            return "https://openapi.baidu.com/oauth/2.0/token";
        }

        public string UserInfo()
        {
            return "https://openapi.baidu.com/rest/2.0/passport/users/getInfo";
        }

        public string Revoke()
        {
            return "https://openapi.baidu.com/rest/2.0/passport/auth/revokeAuthorization";
        }

        public string Refresh()
        {
            return "https://openapi.baidu.com/oauth/2.0/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.BAIDU.ToString();
        }
    }
}