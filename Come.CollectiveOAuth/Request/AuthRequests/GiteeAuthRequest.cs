using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;

namespace Come.CollectiveOAuth.Request
{
    public class GiteeAuthRequest : DefaultAuthRequest
    {
        public GiteeAuthRequest(ClientConfig config) : base(config, new GiteeAuthSource())
        {
        }

        public GiteeAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new GiteeAuthSource(), authStateCache)
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
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.Scope = accessTokenObject.GetString("scope");

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("login");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("avatar_url");
            authUser.Blog = userObj.GetString("blog");
            authUser.Company = userObj.GetString("company");
            authUser.Location = userObj.GetString("address");
            authUser.Email = userObj.GetString("email");
            authUser.Remark = userObj.GetString("bio");
            authUser.Gender = AuthUserGender.Unknown;
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
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