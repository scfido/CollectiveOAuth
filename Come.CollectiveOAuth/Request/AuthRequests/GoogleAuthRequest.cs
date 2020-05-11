using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class GoogleAuthRequest : DefaultAuthRequest
    {
        public GoogleAuthRequest(ClientConfig config) : base(config, new GoogleAuthSource())
        {
        }

        public GoogleAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new GoogleAuthSource(), authStateCache)
        {
        }
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.IdToken = accessTokenObject.GetString("id_token");
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.Scope = accessTokenObject.GetString("scope");

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "Authorization", "Bearer " + authToken.AccessToken }
            };
            var response = HttpUtils.RequestPost(UserInfoUrl(authToken), null, reqParams);
            var userInfo = response;
            var userObj = userInfo.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("sub");
            authUser.Username = userObj.GetString("email");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("picture");
            authUser.Location = userObj.GetString("locale");
            authUser.Email = userObj.GetString("email");
            authUser.Gender = AuthUserGender.Unknown;

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
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
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "openid%20email%20profile" : config.Scope)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken 用户授权后的token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .Build();
        }

        /**
       * 校验请求结果
       *
       * @param response 请求结果
       * @return 如果请求结果正常，则返回Exception
       */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error") || dic.ContainsKey("error_description"))
            {
                throw new Exception($"{dic.GetString("error")}: {dic.GetString("error_description")}");
            }
        }
    }
}