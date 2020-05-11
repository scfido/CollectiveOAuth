using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class StackOverflowAuthRequest : DefaultAuthRequest
    {
        public StackOverflowAuthRequest(ClientConfig config) : base(config, new StackOverflowAuthSource())
        {
        }

        public StackOverflowAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new StackOverflowAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string accessTokenUrl = this.accessTokenUrl(authCallback.Code);

            var reqHeaders = new Dictionary<string, object>
            {
                { "Content-Type", "application/x-www-form-urlencoded" },
            };
            var reqParams = accessTokenUrl.ParseUrlObject();

            var response = HttpUtils.RequestPost(source.AccessToken(), reqParams.SpellParams(), reqHeaders);

            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires");
            return authToken;
        }


        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string userInfoUrl = UrlBuilder.FromBaseUrl(this.source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("site", "stackoverflow")
                .QueryParam("key", this.config.StackOverflowKey)
                .Build();

            var response = HttpUtils.RequestGet(userInfoUrl);
            var responseObj = response.ParseObject();
            this.checkResponse(responseObj);
            var userObj = responseObj.GetString("items").ParseListObject()[0];

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("user_id");
            authUser.Username = userObj.GetString("username");
            authUser.Nickname = userObj.GetString("display_name");
            authUser.Avatar = userObj.GetString("profile_image");
            authUser.Location = userObj.GetString("location");
           
            authUser.Gender = AuthUserGender.Unknown;
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = responseObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
         *
         * @param state state 验证授权流程的参数，可以防止csrf
         * @return 返回授权地址
         * @since 1.9.3
         */
        
        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "read_inbox" : config.Scope)
                .QueryParam("state", GetRealState(state))
                .Build();
        }


        /**
         * 检查响应内容是否正确
         *
         * @param object 请求响应内容
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error"))
            {
                throw new Exception($"{dic.GetString("error_description")}");
            }
        }
    }
}