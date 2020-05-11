using System;

namespace Come.CollectiveOAuth.Enums
{
    public struct EnumModel
    {
        public EnumModel(Enum um)
        {
            this.Value = (int)Convert.ChangeType(um, typeof(int));
            this.Name = um.ToString();
            this.Text = um.GetDesc();
        }
        public int Value { get; set; }
        public string Name { get; set; }
        public string Text { get; set; }
    }
}