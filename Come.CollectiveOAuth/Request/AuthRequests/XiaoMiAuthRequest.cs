using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;

namespace Come.CollectiveOAuth.Request
{
    public class XiaoMiAuthRequest : DefaultAuthRequest
    {
        private static readonly string PREFIX = "&&&START&&&";
        public XiaoMiAuthRequest(ClientConfig config) : base(config, new XiaoMiAuthSource())
        {
        }

        public XiaoMiAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new XiaoMiAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            return getToken(accessTokenUrl(authCallback.Code));
        }

        private AuthToken getToken(string accessTokenUrl)
        {
            string response = HttpUtils.RequestGet(accessTokenUrl);
            string jsonStr = response.Replace(PREFIX, "");
            var accessTokenObject = jsonStr.ParseObject();

            if (accessTokenObject.ContainsKey("error"))
            {
                throw new Exception(accessTokenObject.GetString("error_description"));
            }

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.TokenType = accessTokenObject.GetString("token_type");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.Scope = accessTokenObject.GetString("scope");

            authToken.OpenId = accessTokenObject.GetString("openId");
            authToken.MacAlgorithm = accessTokenObject.GetString("mac_algorithm");
            authToken.MacKey = accessTokenObject.GetString("mac_key");

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            // 获取用户信息
            string userResponse = DoGetUserInfo(authToken);

            var userProfile = userResponse.ParseObject();
            if ("error".Equals(userProfile.GetString("result"), StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception(userProfile.GetString("description"));
            }

            var userObj = userProfile.GetString("data").ParseObject();

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("miliaoNick");
            authUser.Nickname = userObj.GetString("miliaoNick");
            authUser.Avatar = userObj.GetString("miliaoIcon");
            authUser.Email = userObj.GetString("mail");
            authUser.Gender = AuthUserGender.Unknown;

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = userResponse;
            //return authUser;

            // 获取用户邮箱手机号等信息
            string emailPhoneUrl = $"{{https://open.account.xiaomi.com/user/phoneAndEmail}}?clientId={config.ClientId}&token={authToken.AccessToken}";

            string emailResponse = HttpUtils.RequestGet(emailPhoneUrl);
            var userEmailPhone = emailResponse.ParseObject();
            if (!"error".Equals(userEmailPhone.GetString("result"), StringComparison.OrdinalIgnoreCase))
            {
                var emailPhone = userEmailPhone.GetString("data").ParseObject();
                authUser.Email = emailPhone.GetString("email");
            }
            else
            {
                //Log.warn("小米开发平台暂时不对外开放用户手机及邮箱信息的获取");
            }

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
        public override String Authorize(String state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user/profile%20user/openIdV2%20user/phoneAndEmail" : config.Scope)
                .QueryParam("skip_confirm", "false")
                .QueryParam("state", GetRealState(state))
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
                .QueryParam("clientId", config.ClientId)
                .QueryParam("token", authToken.AccessToken)
                .Build();
        }

    }
}