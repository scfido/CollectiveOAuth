using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 淘宝
     */
    public class TaobaoAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://oauth.taobao.com/authorize";
        }

        public string AccessToken()
        {
            return "https://oauth.taobao.com/token";
        }

        public string UserInfo()
        {
            throw new System.NotImplementedException();
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
            return DefaultAuthSourceEnum.TAOBAO.ToString();
        }
    }
}