<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="TotpDemo.Default" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Two-factor authentication demo</title>
    <style>
        .validation {
            font-weight: 600;
        }

        .success {
            color: #2E7D32;
        }

        .failure {
            color: #c62828;
        }
    </style>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <h1>Two-factor authentication demo</h1>

        <h2>Setup</h2>
        <p>
            Open your authenticator app and scan the following QR code:
        </p>
        <img width="200" height="200" src="<%= QRCodeUri %>" alt="<%= AccountKey %>" />
        <p>
            Alternatively, enter the following key:
        </p>
        <p><b><%= AccountKey %></b></p>
        
        <h2>Validate</h2>
        <p><asp:Label runat="server" AssociatedControlID="txtOTP">Authentication code</asp:Label></p>
        <p><asp:TextBox runat="server" ID="txtOTP" MaxLength="6"></asp:TextBox></p>
        <p><asp:Button runat="server" ID="btnLogin" OnClick="btnLogin_Click" Text="Continue" /></p>
        <p><asp:Label runat="server" ID="lblResult"></asp:Label></p>
    </div>
    </form>
</body>
</html>
