using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 支付宝服务窗
     */
    public class AlipayMPAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm";
        }

        public string AccessToken()
        {
            return "https://openapi.alipay.com/gateway.do";
        }

        public string UserInfo()
        {
            return "https://openapi.alipay.com/gateway.do";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            throw new System.NotImplementedException();
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.ALIPAY_MP.ToString();
        }
    }
}