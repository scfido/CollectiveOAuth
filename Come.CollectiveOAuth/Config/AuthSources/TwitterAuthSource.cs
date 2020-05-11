using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * Twitter
     */
    public class TwitterAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://api.twitter.com/oauth/authenticate";
        }

        public string AccessToken()
        {
            return "https://api.twitter.com/oauth/access_token";
        }

        public string UserInfo()
        {
            return "https://api.twitter.com/1.1/users/show.json";
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
            return DefaultAuthSourceEnum.TWITTER.ToString();
        }
    }
}