using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * OSChina开源中国
     */
    public class OschinaAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://www.oschina.net/action/oauth2/authorize";
        }

        public string AccessToken()
        {
            return "https://www.oschina.net/action/openapi/token";
        }

        public string UserInfo()
        {
            return "https://www.oschina.net/action/openapi/user";
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
            return DefaultAuthSourceEnum.OSCHINA.ToString();
        }
    }
}