using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 人人网
     */
    public class RenrenAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://graph.renren.com/oauth/authorize";
        }

        public string AccessToken()
        {
            return "https://graph.renren.com/oauth/token";
        }

        public string UserInfo()
        {
            return "https://api.renren.com/v2/user/get";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://graph.renren.com/oauth/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.RENREN.ToString();
        }
    }
}