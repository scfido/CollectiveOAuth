using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Stack Overflow
     */
    public class StackOverflowAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://stackoverflow.com/oauth";
        }

        public string AccessToken()
        {
            return "https://stackoverflow.com/oauth/access_token/json";
        }

        public string UserInfo()
        {
            return "https://api.stackexchange.com/2.2/me";
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
            return DefaultAuthSourceEnum.STACK_OVERFLOW.ToString();
        }
    }
}