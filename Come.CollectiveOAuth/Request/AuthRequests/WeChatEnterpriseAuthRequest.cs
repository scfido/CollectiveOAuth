using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;

namespace Come.CollectiveOAuth.Request
{
    public class WeChatEnterpriseAuthRequest : DefaultAuthRequest
    {
        public WeChatEnterpriseAuthRequest(ClientConfig config) : base(config, new WechatEnterpriseAuthSource())
        {
        }

        public WeChatEnterpriseAuthRequest(ClientConfig config, IAuthStateCache authStateCache) 
            : base(config, new WechatEnterpriseAuthSource(), authStateCache)
        {
        }

        /**
        * 微信的特殊性，此时返回的信息同时包含 openid 和 access_token
        *
        * @param authCallback 回调返回的参数
        * @return 所有信息
        */
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoGetAuthorizationCode(accessTokenUrl(authCallback.Code));
            var jsonObj = response.ParseObject();

            this.checkResponse(jsonObj);

            var authToken = new AuthToken();
            authToken.AccessToken = jsonObj.GetString("access_token");
            authToken.ExpireIn = jsonObj.GetInt32("expires_in");
            authToken.Code = authCallback.Code;

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);
            var jsonObj = response.ParseObject();
            this.checkResponse(jsonObj);

            // 返回 OpenId 或其他，均代表非当前企业用户，不支持
            if (!jsonObj.ContainsKey("UserId"))
            {
                throw new Exception(AuthResponseStatus.UNIDENTIFIED_PLATFORM.GetDesc());
            }
            string userId = jsonObj.GetString("UserId");
            string userDetailResponse = getUserDetail(authToken.AccessToken, userId);
            var userDetailObj = userDetailResponse.ParseObject();
            this.checkResponse(userDetailObj);

            var authUser = new AuthUser();
            authUser.Username = userDetailObj.GetString("name");
            authUser.Nickname = userDetailObj.GetString("alias");
            authUser.Avatar = userDetailObj.GetString("avatar");
            authUser.Location = userDetailObj.GetString("address");
            authUser.Email = userDetailObj.GetString("email");
            authUser.Uuid = userDetailObj.GetString("userId");
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.Gender = GlobalAuthUtil.GetWechatRealGender(userDetailObj.GetString("gender"));

            authUser.OriginalUser = userDetailObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 校验请求结果
         *
         * @param response 请求结果
         * @return 如果请求结果正常，则返回JSONObject
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("errcode") && dic.GetInt32("errcode") != 0)
            {
                throw new Exception($"errcode: {dic.GetString("errcode")}, errmsg: {dic.GetString("errmsg")}");
            }
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
                .QueryParam("appid", config.ClientId)
                .QueryParam("response_type", "code")
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "snsapi_userinfo" : config.Scope)
                .QueryParam("state", GetRealState(state) + "#wechat_redirect")
                .Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param code 授权码
         * @return 返回获取accessToken的url
         */
        protected override string accessTokenUrl(String code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("corpid", config.ClientId)
                .QueryParam("corpsecret", config.ClientSecret)
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
                .QueryParam("code", authToken.Code)
                .Build();
        }

        /**
         * 用户详情
         *
         * @param accessToken accessToken
         * @param userId      企业内用户id
         * @return 用户详情
         */
        private string getUserDetail(string accessToken, string userId)
        {
            string userDetailUrl = UrlBuilder.FromBaseUrl("https://qyapi.weixin.qq.com/cgi-bin/user/get")
                .QueryParam("access_token", accessToken)
                .QueryParam("userid", userId)
                .Build();
            return HttpUtils.RequestGet(userDetailUrl);
        }
    }
}