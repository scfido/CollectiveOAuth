using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 微博
     */
    public class WeiboAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://api.weibo.com/oauth2/authorize";
        }

        public string AccessToken()
        {
            return "https://api.weibo.com/oauth2/access_token";
        }

        public string UserInfo()
        {
            return "https://api.weibo.com/2/users/show.json";
        }

        public string Revoke()
        {
            return "https://api.weibo.com/oauth2/revokeoauth2";
        }

        public string Refresh()
        {
            throw new System.NotImplementedException();
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.WEIBO.ToString();
        }
    }
}