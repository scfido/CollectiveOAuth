using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 抖音
     */
    public class DouyinAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://open.douyin.com/platform/oauth/connect";
        }

        public string AccessToken()
        {
            return "https://open.douyin.com/oauth/access_token/";
        }

        public string UserInfo()
        {
            return "https://open.douyin.com/oauth/userinfo/";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://open.douyin.com/oauth/refresh_token/";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.DOUYIN.ToString();
        }
    }
}