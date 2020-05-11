using System;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Models
{
    public class AuthResponse
    {
        /**
        * 授权响应状态码
        */
        public int Code { get; set; }

        /**
         * 授权响应信息
         */
        public string Message { get; set; }

        /**
         * 授权响应数据，当且仅当 code = 2000 时返回
         */
        public object Data { get; set; }

        /**
         * 是否请求成功
         *
         * @return true or false
         */
        public bool Ok()
        {
            return this.Code == Convert.ToInt32(AuthResponseStatus.SUCCESS);
        }

        public AuthResponse(int code, string msg, object data = null)
        {
            this.Code = code;
            this.Message = msg;
            this.Data = data;
        }
    }
}