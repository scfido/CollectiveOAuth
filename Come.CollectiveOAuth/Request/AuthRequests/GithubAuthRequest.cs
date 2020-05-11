using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class GithubAuthRequest : DefaultAuthRequest
    {
        public GithubAuthRequest(ClientConfig config) : base(config, new GithubAuthSource())
        {
        }

        public GithubAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new GithubAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseStringObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.Scope = accessTokenObject.GetString("scope");
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
            authUser.Username = userObj.GetString("login");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = userObj.GetString("avatar_url");
            authUser.Blog = userObj.GetString("blog");
            authUser.Company = userObj.GetString("company");
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

        /// <summary>
        /// 重写获取用户信息方法
        /// </summary>
        /// <param name="authToken"></param>
        /// <returns></returns>
        protected override string DoGetUserInfo(AuthToken authToken)
        {
            return HttpUtils.RequestJsonGet(UserInfoUrl(authToken));
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
                .QueryParam("client_id", config.ClientId)
                .QueryParam("response_type", "code")
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user" : config.Scope)
                .QueryParam("state", GetRealState(state) + "#wechat_redirect")
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