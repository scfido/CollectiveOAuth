using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;
using Newtonsoft.Json;

namespace Come.CollectiveOAuth.Request
{
    public class MicrosoftAuthRequest : DefaultAuthRequest
    {
        public MicrosoftAuthRequest(ClientConfig config) : base(config, new MicrosoftAuthSource())
        {
        }

        public MicrosoftAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new MicrosoftAuthSource(), authStateCache)
        {
        }
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            return getToken(accessTokenUrl(authCallback.Code));
        }

        /**
         * 获取token，适用于获取access_token和刷新token
         *
         * @param accessTokenUrl 实际请求token的地址
         * @return token对象
         */
        private AuthToken getToken(string accessTokenUrl)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "Host", "https://login.microsoftonline.com" },
                { "Content-Type", "application/x-www-form-urlencoded" },
            };

            var reqParamDic = GlobalAuthUtil.ParseUrlObject(accessTokenUrl);
            var response = HttpUtils.RequestPost(accessTokenUrl, JsonConvert.SerializeObject(reqParamDic), reqParams);
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.Scope = accessTokenObject.GetString("scope");

            return authToken;
        }


        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var token = authToken.AccessToken;
            var tokenType = authToken.TokenType;
            var jwt = tokenType + " " + token;
            var reqParams = new Dictionary<string, object>
            {
                { "Authorization", jwt },
            };

            var response = HttpUtils.RequestGet(UserInfoUrl(authToken), reqParams);
            var userObj = response.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("userPrincipalName");
            authUser.Nickname = userObj.GetString("displayName");
            authUser.Location = userObj.GetString("officeLocation");
            authUser.Email = userObj.GetString("mail");
            authUser.Gender = AuthUserGender.Unknown;

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 刷新access token （续期）
         *
         * @param authToken 登录成功后返回的Token信息
         * @return AuthResponse
         */
        public override AuthResponse Refresh(AuthToken authToken)
        {
            var token = getToken(RefreshTokenUrl(authToken.RefreshToken));
            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), token);
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
                .QueryParam("response_mode", "query")
                .QueryParam("scope", "offline_access%20" + (config.Scope.IsNullOrWhiteSpace() ? "user.read%20mail.read" : config.Scope))
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param code 授权code
         * @return 返回获取accessToken的url
         */
        protected override string accessTokenUrl(string code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("code", code)
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("grant_type", "authorization_code")
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user.read%20mail.read" : config.Scope)
                .QueryParam("redirect_uri", config.RedirectUri)
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
            return UrlBuilder.FromBaseUrl(source.UserInfo()).Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param refreshToken 用户授权后的token
         * @return 返回获取accessToken的url
         */
        protected override string RefreshTokenUrl(string refreshToken)
        {
            return UrlBuilder.FromBaseUrl(source.Refresh())
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("refresh_token", refreshToken)
                .QueryParam("grant_type", "refresh_token")
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user.read%20mail.read" : config.Scope)
                .QueryParam("redirect_uri", config.RedirectUri)
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
                throw new Exception(dic.GetString("error_description"));
            }
        }
    }
}