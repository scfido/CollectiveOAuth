using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Google(谷歌)
     */
    public class GoogleAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://accounts.google.com/o/oauth2/v2/auth";
        }

        public string AccessToken()
        {
            return "https://www.googleapis.com/oauth2/v4/token";
        }

        public string UserInfo()
        {
            return "https://www.googleapis.com/oauth2/v3/userinfo";
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
            return DefaultAuthSourceEnum.GOOGLE.ToString();
        }
    }
}