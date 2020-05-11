using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Models
{
    public class AuthUser
    {
        /**
        * 用户第三方系统的唯一id。在调用方集成改组件时，可以用uuid + source唯一确定一个用户
        *
        * @since 1.3.3
        */
        public string Uuid { get; set; }
        /**
         * 用户名
         */
        public string Username { get; set; }
        /**
         * 用户昵称
         */
        public string Nickname { get; set; }
        /**
         * 用户头像
         */
        public string Avatar { get; set; }
        /**
         * 用户网址
         */
        public string Blog { get; set; }
        /**
         * 所在公司
         */
        public string Company { get; set; }
        /**
         * 位置
         */
        public string Location { get; set; }
        /**
         * 用户邮箱
         */
        public string Email { get; set; }
        /**
         * 用户备注（各平台中的用户个人介绍）
         */
        public string Remark { get; set; }
        /**
         * 性别
         */
        public AuthUserGender Gender { get; set; }
        /**
         * 用户来源
         */
        public string Source { get; set; }
        /**
         * 用户授权的token信息
         */
        public AuthToken Token { get; set; }

        /// <summary>
        /// 是否启用
        /// </summary>
        public bool Enable { get; set; } // Todo:完善各账户中的是否启用设置

        /// <summary>
        /// 原有的用户信息(第三方返回的)
        /// </summary>
        public object OriginalUser { get; set; }

        public string OriginalUserStr { get; set; }
    }
}