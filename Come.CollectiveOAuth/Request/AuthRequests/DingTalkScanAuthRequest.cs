using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;
using Newtonsoft.Json;
using DingTalk.Api;
using DingTalk.Api.Response;
using DingTalk.Api.Request;

namespace Come.CollectiveOAuth.Request
{
    public class DingTalkScanAuthRequest : DefaultAuthRequest
    {
        public DingTalkScanAuthRequest(ClientConfig config) : base(config, new DingTalkScanAuthSource())
        {
        }

        public DingTalkScanAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new DingTalkScanAuthSource(), authStateCache)
        {
        }


        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var authToken = new AuthToken();
            authToken.AccessCode = authCallback.Code;
            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var client = new DefaultDingTalkClient(source.UserInfo());
            OapiSnsGetuserinfoBycodeRequest req = new OapiSnsGetuserinfoBycodeRequest();
            req.TmpAuthCode = authToken.AccessCode;
            OapiSnsGetuserinfoBycodeResponse response = client.Execute(req, config.ClientId, config.ClientSecret);

            if (response.IsError)
            {
                throw new Exception(response.Errmsg);
            }
            var userObj = response.UserInfo;

            authToken.OpenId = userObj.Openid;
            authToken.UnionId = userObj.Unionid;

            var authUser = new AuthUser();
            authUser.Uuid = userObj.Unionid;
            authUser.Username = userObj.Nick;
            authUser.Nickname = userObj.Nick;
            authUser.Gender = AuthUserGender.Unknown;

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = response;
            authUser.OriginalUserStr = JsonConvert.SerializeObject(response);
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
                .QueryParam("appid", config.ClientId)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "snsapi_login" : config.Scope)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .Build();
        }

    }
}