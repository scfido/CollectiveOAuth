namespace Come.CollectiveOAuth.Models
{
    /**
     * 授权所需的token
     * @author wei.fu
     * @since 1.8
     */
    public class AuthToken
    {
        public string AccessToken { get; set; }
        public int ExpireIn { get; set; }
        public string RefreshToken { get; set; }
        public string Uid { get; set; }
        public string OpenId { get; set; }
        public string AccessCode { get; set; }
        public string UnionId { get; set; }

        /**
         * Google附带属性
         */
        public string Scope { get; set; }
        public string TokenType { get; set; }
        public string IdToken { get; set; }

        /**
         * 小米附带属性
         */
        public string MacAlgorithm { get; set; }
        public string MacKey { get; set; }

        /**
         * 企业微信附带属性
         *
         * @since 1.10.0
         */
        public string Code { get; set; }

        /**
         * Twitter附带属性
         *
         * @since 1.13.0
         */
        public string OauthToken { get; set; }
        public string OauthTokenSecret { get; set; }
        public string UserId { get; set; }
        public string ScreenName { get; set; }
        public bool OauthCallbackConfirmed { get; set; }

    }
}