using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class GitlabAuthRequest : DefaultAuthRequest
    {
        public GitlabAuthRequest(ClientConfig config) : base(config, new GitlabAuthSource())
        {
        }

        public GitlabAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new GitlabAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.IdToken = accessTokenObject.GetString("id_token");
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.Scope = accessTokenObject.GetString("scope");
            authToken.Code = authCallback.Code;

            return authToken;
        }


        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject();

            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("username");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("avatar_url");
            authUser.Blog = userObj.GetString("web_url");
            authUser.Company = userObj.GetString("organization");
            authUser.Location = userObj.GetString("location");
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
         * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
         *
         * @param state state 验证授权流程的参数，可以防止csrf
         * @return 返回授权地址
         * @since 1.11.0
         */
        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "read_user+openid+profile+email" : config.Scope)
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
            // user 验证异常
            if (dic.ContainsKey("message"))
            {
                throw new Exception($"{dic.GetString("message")}");
            }
        }

    }
}