using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 腾讯QQ
     */
    public class QQAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://graph.qq.com/oauth2.0/authorize";
        }

        public string AccessToken()
        {
            return "https://graph.qq.com/oauth2.0/token";
        }

        public string UserInfo()
        {
            return "https://graph.qq.com/user/get_user_info";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://graph.qq.com/oauth2.0/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.QQ.ToString();
        }
    }
}