using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 今日头条
     */
    public class ToutiaoAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://open.snssdk.com/auth/authorize";
        }

        public string AccessToken()
        {
            return "https://open.snssdk.com/auth/token";
        }

        public string UserInfo()
        {
            return "https://open.snssdk.com/data/user_profile";
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
            return DefaultAuthSourceEnum.TOUTIAO.ToString();
        }
    }
}