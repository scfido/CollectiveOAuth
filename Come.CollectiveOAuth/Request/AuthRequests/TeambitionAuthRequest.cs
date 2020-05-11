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
    public class TeambitionAuthRequest : DefaultAuthRequest
    {
        public TeambitionAuthRequest(ClientConfig config) : base(config, new GithubAuthSource())
        {
        }

        public TeambitionAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new GithubAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var reqHeaders = new Dictionary<string, object>
            {
                { "Content-Type", "application/x-www-form-urlencoded" },
            };
            var reqParams = new Dictionary<string, object>
            {
                { "client_id", config.ClientId },
                { "client_secret", config.ClientSecret },
                { "code", authCallback.Code },
                { "grant_type", "code" },
            };

            var response = HttpUtils.RequestPost(source.AccessToken(), reqParams.SpellParams(), reqHeaders);

            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var accessToken = authToken.AccessToken;
            var reqHeaders = new Dictionary<string, object>
            {
                { "Authorization", "OAuth2 " + accessToken },
            };

            var response = HttpUtils.RequestGet(source.UserInfo(), reqHeaders);
            var userObj = response.ParseObject();

            this.checkResponse(userObj);
            authToken.Uid = userObj.GetString("_id");

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("_id");
            authUser.Username = userObj.GetString("name");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("avatarUrl");
            authUser.Blog = userObj.GetString("website");
            authUser.Location = userObj.GetString("location");
            authUser.Email = userObj.GetString("email");
            authUser.Gender = AuthUserGender.Unknown;
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        
        public override AuthResponse Refresh(AuthToken oldToken)
        {
            string uid = oldToken.Uid;
            string refreshToken = oldToken.RefreshToken;
            var reqHeaders = new Dictionary<string, object>
            {
                { "Content-Type", "application/x-www-form-urlencoded" },
            };
            var reqParams = new Dictionary<string, object>
            {
                { "_userId", uid },
                { "refresh_token", refreshToken },
            };

            var response = HttpUtils.RequestPost(source.Refresh(), reqParams.SpellParams(), reqHeaders);

            var refreshTokenObject = response.ParseObject();

            this.checkResponse(refreshTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = refreshTokenObject.GetString("access_token");
            authToken.RefreshToken = refreshTokenObject.GetString("refresh_token");

            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), authToken);
        }


        /**
        * 校验请求结果
        *
        * @param response 请求结果
        * @return 如果请求结果正常，则返回Exception
        */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("message") && dic.ContainsKey("name"))
            {
                throw new Exception($"{dic.GetString("getString")}, {dic.GetString("name")}");
            }
        }
    }
}