using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 小米开放平台
     */
    public class XiaoMiAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://account.xiaomi.com/oauth2/authorize";
        }

        public string AccessToken()
        {
            return "https://account.xiaomi.com/oauth2/token";
        }

        public string UserInfo()
        {
            return "https://open.account.xiaomi.com/user/profile";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://account.xiaomi.com/oauth2/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.XIAOMI.ToString();
        }
    }
}