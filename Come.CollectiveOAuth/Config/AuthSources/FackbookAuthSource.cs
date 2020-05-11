using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Facebook
     */
    public class FackbookAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://www.facebook.com/v3.3/dialog/oauth";
        }

        public string AccessToken()
        {
            return "https://graph.facebook.com/v3.3/oauth/access_token";
        }

        public string UserInfo()
        {
            return "https://graph.facebook.com/v3.3/me";
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
            return DefaultAuthSourceEnum.FACEBOOK.ToString();
        }
    }
}