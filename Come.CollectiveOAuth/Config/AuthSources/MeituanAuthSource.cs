using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 美团
     */
    public class MeituanAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://openapi.waimai.meituan.com/oauth/authorize";
        }

        public string AccessToken()
        {
            return "https://openapi.waimai.meituan.com/oauth/access_token";
        }

        public string UserInfo()
        {
            return "https://openapi.waimai.meituan.com/oauth/userinfo";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://openapi.waimai.meituan.com/oauth/refresh_token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.MEITUAN.ToString();
        }
    }
}