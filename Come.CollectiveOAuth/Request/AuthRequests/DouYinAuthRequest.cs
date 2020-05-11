using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class DouyinAuthRequest : DefaultAuthRequest
    {
        public DouyinAuthRequest(ClientConfig config) : base(config, new DouyinAuthSource())
        {
        }

        public DouyinAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new DouyinAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            return this.getToken(accessTokenUrl(authCallback.Code));
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);
            var userInfoObject = response.ParseObject();
            this.checkResponse(userInfoObject);
            var userObj = userInfoObject.GetString("data").ParseObject();

            var location = $"{userObj.GetString("country")}-{userObj.GetString("province")}-{userObj.GetString("city")}";
            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("union_id");
            authUser.Username = userObj.GetString("nickname");
            authUser.Nickname = userObj.GetString("nickname");
            authUser.Avatar = userObj.GetString("avatar");
            authUser.Location = location;
            authUser.Remark = userObj.GetString("description");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender"));

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        public override AuthResponse Refresh(AuthToken oldToken)
        {
            var data = getToken(RefreshTokenUrl(oldToken.RefreshToken));
            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), data);
        }


        /**
         * 获取token，适用于获取access_token和刷新token
         *
         * @param accessTokenUrl 实际请求token的地址
         * @return token对象
         */
        private AuthToken getToken(string accessTokenUrl)
        {
            var response = HttpUtils.RequestPost(accessTokenUrl);
            string accessTokenStr = response;
            var tokenObj = accessTokenStr.ParseObject();
            this.checkResponse(tokenObj);
            var accessTokenObject = tokenObj.GetString("data").ParseObject();

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                OpenId = accessTokenObject.GetString("open_id"),
                ExpireIn = accessTokenObject.GetInt32("token_type"),
                RefreshToken = accessTokenObject.GetString("refresh_token"),
                Scope = accessTokenObject.GetString("scope")
            };

            return authToken;
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
                .QueryParam("client_key", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user_info" : config.Scope)
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param code oauth的授权码
         * @return 返回获取accessToken的url
         */
        protected override string accessTokenUrl(string code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("code", code)
                .QueryParam("client_key", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("grant_type", "authorization_code")
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken oauth返回的token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("open_id", authToken.OpenId)
                .Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param refreshToken oauth返回的refreshtoken
         * @return 返回获取accessToken的url
         */
        protected override string RefreshTokenUrl(string refreshToken)
        {
            return UrlBuilder.FromBaseUrl(source.Refresh())
                .QueryParam("client_key", config.ClientId)
                .QueryParam("refresh_token", refreshToken)
                .QueryParam("grant_type", "refresh_token")
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
            string message = dic.GetString("message");
            var data = dic.GetString("data").ParseObject();
            int errorCode = data.GetInt32("error_code");
            if ("error".Equals(message) || errorCode != 0)
            {
                throw new Exception(data.GetString("description"));
            }
        }
    }
}