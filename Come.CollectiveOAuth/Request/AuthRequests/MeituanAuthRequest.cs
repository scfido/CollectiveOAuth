using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class MeituanAuthRequest : DefaultAuthRequest
    {
        public MeituanAuthRequest(ClientConfig config) : base(config, new MeituanAuthSource())
        {
        }

        public MeituanAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new MeituanAuthSource(), authStateCache)
        {
        }
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "app_id", config.ClientId },
                { "secret", config.ClientSecret },
                { "code", authCallback.Code },
                { "grant_type", "authorization_code" },
            };

            var response = HttpUtils.RequestFormPost(source.AccessToken(), reqParams.SpellParams());
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                ExpireIn = accessTokenObject.GetInt32("expires_in"),
                RefreshToken = accessTokenObject.GetString("refresh_token"),
                Code = authCallback.Code
            };

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "app_id", config.ClientId },
                { "secret", config.ClientSecret },
                { "access_token", authToken.AccessToken },
            };

            var response = HttpUtils.RequestFormPost(source.UserInfo(), reqParams.SpellParams());
            var userObj = response.ParseObject();

            this.checkResponse(userObj);

            var authUser = new AuthUser
            {
                Uuid = userObj.GetString("openid"),
                Username = userObj.GetString("nickname"),
                Nickname = userObj.GetString("nickname"),
                Avatar = userObj.GetString("avatar"),
                Gender = AuthUserGender.Unknown,
                Token = authToken,
                Source = source.GetName(),
                OriginalUser = userObj,
                OriginalUserStr = response
            };
            return authUser;
        }

        public override AuthResponse Refresh(AuthToken oldToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "app_id", config.ClientId },
                { "secret", config.ClientSecret },
                { "refresh_token", oldToken.RefreshToken },
                { "grant_type", "refresh_token" },
            };

            var response = HttpUtils.RequestFormPost(source.Refresh(), reqParams.SpellParams());
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                RefreshToken = accessTokenObject.GetString("refresh_token"),
                ExpireIn = accessTokenObject.GetInt32("expires_in")
            };

            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), authToken);
        }


        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("app_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .QueryParam("scope", config.Scope)
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
            if (dic.ContainsKey("error_code"))
            {
                throw new Exception($"{dic.GetString("error_msg")}");
            }
        }
    }
}