using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class PinterestAuthRequest : DefaultAuthRequest
    {
        public PinterestAuthRequest(ClientConfig config) : base(config, new PinterestAuthSource())
        {
        }

        public PinterestAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new PinterestAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                TokenType = accessTokenObject.GetString("token_type"),
                Code = authCallback.Code
            };

            return authToken;
        }

        
        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string userinfoUrl = UserInfoUrl(authToken);
            var response = HttpUtils.RequestGet(userinfoUrl);
            var responseObj = response.ParseObject();
            this.checkResponse(responseObj);

            var userObj = responseObj.GetString("data").ParseObject();

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("username");
            authUser.Nickname = userObj.GetString("first_name") + userObj.GetString("last_name");
            authUser.Avatar = getAvatarUrl(userObj);
            authUser.Remark = userObj.GetString("bio");
            authUser.Gender = AuthUserGender.Unknown;
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = responseObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }


        private string getAvatarUrl(Dictionary<string, object> userObj)
        {
            // image is a map data structure
            var jsonObject = userObj.GetString("image").ParseObject();
            if (jsonObject.Count == 0)
            {
                return null;
            }
            return jsonObject.GetString("60x60").ParseObject().GetString("url");
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
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "read_public": config.Scope)
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("fields", "id,username,first_name,last_name,bio,image")
                .Build();
        }


        /**
         * 检查响应内容是否正确
         *
         * @param object 请求响应内容
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("status") && "failure".Equals(dic.GetString("status")))
            {
                throw new Exception($"{dic.GetString("message")}");
            }
        }
    }
}