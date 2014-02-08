using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using DotNetOpenAuth.AspNet.Clients;
using Newtonsoft.Json;

namespace DotNetOpenAuth.TaobaoOAuth2
{
    /// <summary>
    /// A DotNetOpenAuth client for taobao authentication using OAuth2.
    /// Reference: http://developers.facebook.com/docs/howtos/login/server-side-login/
    /// </summary>
    public class TaobaoOAuth2Client : OAuth2Client
    {
        #region Constants and Fields

        /// <summary>
        /// The authorization endpoint.
        /// </summary>
        private const string AuthorizationEndpoint = "https://oauth.taobao.com/authorize";

        /// <summary>
        /// The token endpoint.
        /// </summary>
        private const string TokenEndpoint = "https://oauth.taobao.com/token";

        /// <summary>
        /// The user info endpoint.
        /// </summary>
        private const string UserInfoEndpoint = "https://graph.facebook.com/me";

        /// <summary>
        /// The app id.
        /// </summary>
        private readonly string _appId;

        /// <summary>
        /// The app secret.
        /// </summary>
        private readonly string _appSecret;

        /// <summary>
        /// The requested scopes.
        /// </summary>
        private readonly string[] _requestedScopes;


        private Dictionary<string, string> _authenticationData;

        #endregion

        /// <summary>
        /// Creates a new Facebook OAuth2 client, requesting the default "email" scope.
        /// </summary>
        /// <param name="appId">The Facebook App Id</param>
        /// <param name="appSecret">The Facebook App Secret</param>
        public TaobaoOAuth2Client(string appId, string appSecret)
            : this(appId, appSecret, new[] { "email" }) { }

        /// <summary>
        /// Creates a new Facebook OAuth2 client.
        /// </summary>
        /// <param name="appId">The Facebook App Id</param>
        /// <param name="appSecret">The Facebook App Secret</param>
        /// <param name="requestedScopes">One or more requested scopes, passed without the base URI.</param>
        public TaobaoOAuth2Client(string appId, string appSecret, params string[] requestedScopes)
            : base("taobao")
        {
            if (string.IsNullOrWhiteSpace(appId))
                throw new ArgumentNullException("appId");

            if (string.IsNullOrWhiteSpace(appSecret))
                throw new ArgumentNullException("appSecret");

            if (requestedScopes == null)
                throw new ArgumentNullException("requestedScopes");

            if (requestedScopes.Length == 0)
                throw new ArgumentException("One or more scopes must be requested.", "requestedScopes");

            _appId = appId;
            _appSecret = appSecret;
            _requestedScopes = requestedScopes;

            _authenticationData = new Dictionary<string, string>();
        }

        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var state = string.IsNullOrEmpty(returnUrl.Query) ? string.Empty : returnUrl.Query.Substring(1);

            return BuildUri(AuthorizationEndpoint, new NameValueCollection
                {
                    { "client_id", _appId },
                    { "response_type", "code" },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
                    { "state", state },
                });
        }

        // To leverage the OAuth2Client class, 
        // we use this method to pass additional data to the use of this client. 
        protected override IDictionary<string, string> GetUserData(string accessToken)
        {
            // Add some dummy data; otherwise, an exception throws out.

            _authenticationData.Add("id", "12345678");

            return _authenticationData; 
        }

        // To be removed
        /*
        public class AccessTokenResponse
        {
            string access_token;
            string token_type;
            string refresh_token;
            int expires_in;
            int re_expires_in;
            int r1_expires_in;
            int r2_expires_in;
            int w1_expires_in;
            int w2_expires_in;
            string taobao_user_nick;
            string taobao_user_id;
            string sub_taobao_user_id;
            string sub_taobao_user_nick;

            public string AccessToken { get { return access_token; } }
            public string RefreshToken { get { return refresh_token; } }
        };
         */


        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            // Create a request using a URL that can receive a post.
            WebRequest request = WebRequest.Create(TokenEndpoint);
            // Set the Method property of the request to POST.
            request.Method = "POST";

            // Create POST data and convert it to a byte array.
            string postData = string.Format("client_id={0}&client_secret={1}&grant_type={2}&code={3}&redirect_uri={4}",
                HttpUtility.UrlEncode(_appId),
                HttpUtility.UrlEncode(_appSecret),
                HttpUtility.UrlEncode("authorization_code"),
                HttpUtility.UrlEncode(authorizationCode),
                HttpUtility.UrlEncode(returnUrl.AbsoluteUri));

            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            // Set the ContentType property of the WebRequest.
            request.ContentType = "application/x-www-form-urlencoded";
            // Set the ContentLength property of the WebRequest.
            request.ContentLength = byteArray.Length;
            // Get the request stream.
            Stream dataStream = request.GetRequestStream();
            // Write the data to the request stream.
            dataStream.Write(byteArray, 0, byteArray.Length);
            // Close the Stream object.
            dataStream.Close();
            // Get the response.
            using (var webResponse = request.GetResponse())
            {
                var responseStream = webResponse.GetResponseStream();
                if (responseStream == null)
                    return null;

                using (var reader = new StreamReader(responseStream))
                {
                    var json = reader.ReadToEnd();
                    // Convert the return msg into an object.
                    JavaScriptSerializer json_serializer = new JavaScriptSerializer();
                    // AccessTokenResponse tokenResponse = json_serializer.Deserialize<AccessTokenResponse>(response);
                    var extraData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                    _authenticationData = extraData.ToDictionary(x => x.Key, x => x.Value.ToString());

                    string res = String.Empty;
                    _authenticationData.TryGetValue("access_token", out res);
                    return res;
                }
            }
        }

        private static Uri BuildUri(string baseUri, NameValueCollection queryParameters)
        {
            var q = HttpUtility.ParseQueryString(string.Empty);
            q.Add(queryParameters);
            var builder = new UriBuilder(baseUri) { Query = q.ToString() };
            return builder.Uri;
        }

        /// <summary>
        /// Facebook works best when return data be packed into a "state" parameter.
        /// This should be called before verifying the request, so that the url is rewritten to support this.
        /// </summary>
        public static void RewriteRequest()
        {
            var ctx = HttpContext.Current;

            var stateString = HttpUtility.UrlDecode(ctx.Request.QueryString["state"]);
            if (stateString == null || !stateString.Contains("__provider__=taobao"))
                return;

            var q = HttpUtility.ParseQueryString(stateString);
            q.Add(ctx.Request.QueryString);
            q.Remove("state");

            ctx.RewritePath(ctx.Request.Path + "?" + q);
        }
    }
}
