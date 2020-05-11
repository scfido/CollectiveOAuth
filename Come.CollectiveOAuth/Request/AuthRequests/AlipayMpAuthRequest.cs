using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Cache;
using Aop.Api;
using Aop.Api.Request;
using Aop.Api.Response;
using Newtonsoft.Json;

namespace Come.CollectiveOAuth.Request
{
    public partial class AlipayMpAuthRequest : DefaultAuthRequest
    {
        private IAopClient aopClient;
        public AlipayMpAuthRequest(ClientConfig config) : base(config, new AlipayMPAuthSource())
        {
            aopClient = new DefaultAopClient(source.AccessToken(), config.ClientId, config.ClientSecret, "json", "1.0", "RSA2", config.alipayPublicKey, "GBK", false);
        }

        public AlipayMpAuthRequest(ClientConfig config, IAuthStateCache authStateCache) : base(config, new AlipayMPAuthSource(), authStateCache)
        {
            aopClient = new DefaultAopClient(source.AccessToken(), config.ClientId, config.ClientSecret, "json", "1.0", "RSA2", config.alipayPublicKey, "GBK", false);
        }

        /**
          * 微信的特殊性，此时返回的信息同时包含 openid 和 access_token
          *
          * @param authCallback 回调返回的参数
          * @return 所有信息
          */
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            AlipaySystemOauthTokenRequest request = new AlipaySystemOauthTokenRequest();
            request.GrantType = "authorization_code";
            request.Code = authCallback.AuthCode;
            AlipaySystemOauthTokenResponse response = null;
            try
            {
                response = this.aopClient.Execute(request);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
            if (response.IsError)
            {
                throw new Exception(response.SubMsg);
            }

            var authToken = new AuthToken();
            authToken.AccessToken = response.AccessToken;
            authToken.Uid = response.UserId;
            authToken.ExpireIn = Convert.ToInt32(response.ExpiresIn);
            authToken.RefreshToken = response.RefreshToken;
            authToken.UserId = response.AlipayUserId;

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string accessToken = authToken.AccessToken;
            AlipayUserInfoShareRequest request = new AlipayUserInfoShareRequest();
            AlipayUserInfoShareResponse response = null;
            try
            {
                response = this.aopClient.Execute(request, accessToken);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message, e);
            }
            if (response.IsError)
            {
                throw new Exception(response.SubMsg);
            }

            string province = response.Province, city = response.City;
            string location = string.Format("{0} {1}", !province.IsNullOrWhiteSpace() ? "" : province, !city.IsNullOrWhiteSpace() ? "" : city);

            var authUser = new AuthUser();
            authUser.Username = response.UserName.IsNullOrWhiteSpace() ? response.NickName : response.UserName;
            authUser.Nickname = response.NickName;
            authUser.Avatar = response.Avatar;
            authUser.Location = location;
            authUser.Uuid = response.UserId;
            authUser.Gender = GlobalAuthUtil.GetRealGender(response.Gender);
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
                .QueryParam("app_id", config.ClientId)
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "auth_user" : config.Scope)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .Build();
        }
    }
}