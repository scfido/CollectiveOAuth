using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 微软
     */
    public class MicrosoftAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
        }

        public string AccessToken()
        {
            return "https://login.microsoftonline.com/common/oauth2/v2.0/token";
        }

        public string UserInfo()
        {
            return "https://graph.microsoft.com/v1.0/me";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://login.microsoftonline.com/common/oauth2/v2.0/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.MICROSOFT.ToString();
        }
    }
}