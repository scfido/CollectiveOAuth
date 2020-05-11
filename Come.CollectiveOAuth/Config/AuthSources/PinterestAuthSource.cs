using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Pinterest
     */
    public class PinterestAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://api.pinterest.com/oauth";
        }

        public string AccessToken()
        {
            return "https://api.pinterest.com/v1/oauth/token";
        }

        public string UserInfo()
        {
            return "https://api.pinterest.com/v1/me";
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
            return DefaultAuthSourceEnum.PINTEREST.ToString();
        }
    }
}