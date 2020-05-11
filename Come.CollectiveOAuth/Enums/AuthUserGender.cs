using System.ComponentModel;

namespace Come.CollectiveOAuth.Enums
{
    public enum AuthUserGender
    {
        [Description("男")]
        Male=1,
        [Description("女")]
        Female = 0,
        [Description("未知")]
        Unknown = -1
    }
}