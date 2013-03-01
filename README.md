DotNetOpenAuth OAuth2 Client for Facebook
======================================

## Setup

 1. Setup your Facebook App using the [Facebook developer apps site](https://developers.facebook.com/apps).
    Detailed instructions [here](http://ben.onfabrik.com/posts/oauth-providers#facebook)

 2. Install this library from [NuGet](https://nuget.org/packages/DotNetOpenAuth.FacebookOAuth2), or compile from source and reference.

 3. Register the client instead of the existing Facebook OpenId client.

        var client = new FacebookOAuth2Client("yourAppId", "yourAppSecret");
        var extraData = new Dictionary<string, object>();
        OAuthWebSecurity.RegisterClient(client, "Facebook", extraData);

## Usage

Just like any other `OAuthWebSecurity` client, except you need one extra hook:

        // add this line
        FacebookOAuth2Client.RewriteRequest();

        // it belongs right before your existing call to
        OAuthWebSecurity.VerifyAuthentication(....)

This is needed because Facebook requires that any extra querystring parameters for the
redirect be packed into a single parameter called `state`.  Since `OAuthWebSecurity` needs
two parameters, `__provider__` and `__sid__` - we have to rewrite the url.

Reference: http://developers.facebook.com/docs/howtos/login/server-side-login/


## Disclaimer

I don't work for Facebook, Microsoft, or DNOA.  This is released under the [MIT](LICENCE.txt) licence.  Do what you want with it.
