using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 企业微信
     */
    public class WechatEnterpriseAuthSource : IAuthSource
    {
        
        public string AccessToken()
        {
            return "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
        }

        public string Authorize()
        {
            //return "https://open.work.weixin.qq.com/wwopen/sso/qrConnect";
            return "https://open.weixin.qq.com/connect/oauth2/authorize";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.WECHAT_ENTERPRISE.ToString();
        }

        public string Refresh()
        {
            throw new System.NotImplementedException();
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string UserInfo()
        {
            return "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";
        }
    }
}