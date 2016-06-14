using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Decos.TwoFactorAuthentication;

namespace TotpDemo
{
    public partial class Default : System.Web.UI.Page
    {
        public const string TotpSecret = "TotpSecret";

        public string QRCodeUri { get; set; }

        public string AccountKey { get; set; }

        protected void Page_Init(object sender, EventArgs e)
        {
            var provider = GetProvider();

            var text = provider.GetQRCodeUri("r.verdoes@decos.com", "Decos IDP");
            QRCodeUri = "https://chart.googleapis.com/chart?cht=qr&chs=400x400&chl="
                + Uri.EscapeDataString(text);
            AccountKey = provider.Key;
        }

        public TotpProvider GetProvider()
        {
            var key = Session[TotpSecret] as string;
            if (key != null)
            {
                return new TotpProvider(key);
            }
            else
            {
                var provider = TotpProvider.CreateNew();
                Session[TotpSecret] = provider.Key;
                return provider;
            }
        }

        protected void btnLogin_Click(object sender, EventArgs e)
        {
            var provider = GetProvider();
            if (provider.ValidateToken(txtOTP.Text, 1))
            {
                lblResult.CssClass = "validation success";
                lblResult.Text = "Authentication code is valid!";
            }
            else
            {
                lblResult.CssClass = "validation failure";
                lblResult.Text = "The code you entered is not valid, please try again.";
            }
        }
    }
}