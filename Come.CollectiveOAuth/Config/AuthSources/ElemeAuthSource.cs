using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Config
{
    /**
     * 饿了么
     */
    public class ElemeAuthSource : IAuthSource
    {
        public string Authorize()
        {
            return "https://open-api.shop.ele.me/authorize";
        }

        public string AccessToken()
        {
            return "https://open-api.shop.ele.me/token";
        }

        public string UserInfo()
        {
            return "https://open-api.shop.ele.me/api/v1/";
        }

        public string Revoke()
        {
            throw new System.NotImplementedException();
        }

        public string Refresh()
        {
            return "https://open-api.shop.ele.me/token";
        }

        public string GetName()
        {
            return DefaultAuthSourceEnum.ELEME.ToString();
        }
    }
}