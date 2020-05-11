using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 钉钉扫码
     */
    public class DingTalkScanAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://oapi.dingtalk.com/connect/qrconnect";
        }

        public string AccessToken()
        {
            throw new System.NotImplementedException(AuthResponseStatus.UNSUPPORTED.GetDesc());
        }

        public string UserInfo()
        {
            return "https://oapi.dingtalk.com/sns/getuserinfo_bycode"; ;
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
            return DefaultAuthSourceEnum.DINGTALK_SCAN.ToString();
        }
    }
}