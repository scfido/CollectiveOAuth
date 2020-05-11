using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 微信开放平台
     */
    public class WechatOpenAuthSource : IAuthSource
    {
        public string AccessToken()
        {
            return "https://api.weixin.qq.com/sns/oauth2/access_token";
        }

        public string Authorize()
        {
            return "https://open.weixin.qq.com/connect/qrconnect";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.WECHAT_OPEN.ToString();
        }

        public string Refresh()
        {
            return "https://api.weixin.qq.com/sns/oauth2/refresh_token";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string UserInfo()
        {
            return "https://api.weixin.qq.com/sns/userinfo";
        }
    }
}