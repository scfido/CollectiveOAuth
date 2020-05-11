using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class OschinaAuthRequest : DefaultAuthRequest
    {
        public OschinaAuthRequest(ClientConfig config) : base(config, new OschinaAuthSource())
        {
        }

        public OschinaAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new OschinaAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.Uid = accessTokenObject.GetString("uid");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.Code = authCallback.Code;
            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);

            var userObj = response.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("name");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("avatar");
            authUser.Blog = userObj.GetString("url");
            authUser.Location = userObj.GetString("location");
            authUser.Email = userObj.GetString("email");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender"));

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 返回获取accessToken的url
         *
         * @param code 授权回调时带回的授权码
         * @return 返回获取accessToken的url
         */
        protected override string accessTokenUrl(string code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("code", code)
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("grant_type", "authorization_code")
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("dataType", "json")
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
                .QueryParam("dataType", "json")
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
            if (dic.ContainsKey("error"))
            {
                throw new Exception($"{dic.GetString("error_description")}");
            }
        }
    }
}