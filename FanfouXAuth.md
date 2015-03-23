# XAuth #
xAuth是OAuth的简化版本，主要为了解决各种客户端的跳转难题和简化验证流程。

申请了OAuth的开发者，只要拥有合法的consumer\_key和consumer\_secret, 就天然可以使用xAuth验证，并无其他限制。但是不排除以后对滥用xAuth的应用实施措施的可能性，因为恶意的应用可能仍然会保留用户的登录名和密码。

# XAuth 流程 #
oAuth验证要使用三个URL, request\_token, authorize以及access\_token, xAuth验证则只保留最后一个，access\_token. 只是额外增加了三个字段作为参数
  * x\_auth\_username: 用户名字段，可以传递饭否登录名以及登录邮件
  * x\_auth\_password: 密码字段，目前只支持明文方式
  * x\_auth\_mode: 标识字段，填入"client\_auth" 即可

需要注意的是，oauth\_signature字段必须对以上三个x\_auth字段一并校验签名。

# 实例代码 #
以下是一个xAuth客户端的简单实例, 使用python编写，需要先安装oauth库.

```
import sys, urllib, oauth, re
from urllib2 import Request, urlopen

consumer_key = '...'   # 应用key
consumer_secret = '...'  # 应用secret
access_token_url = 'http://fanfou.com/oauth/access_token'
verify_url = 'http://api.fanfou.com/account/verify_credentials.xml'

def request_to_header(request, realm=''):
    """Serialize as a header for an HTTPAuth request."""
    auth_header = 'OAuth realm="%s"' % realm
        # Add the oauth parameters.
    if request.parameters:
        for k, v in request.parameters.iteritems():
            if k.startswith('oauth_') or k.startswith('x_auth_'):
                auth_header += ', %s="%s"' % (k, oauth.escape(str(v)))
    return {'Authorization': auth_header}

# 从command line 参数获得用户名和密码
username = sys.argv[1]
passwd = sys.argv[2]

consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
params = {}
params["x_auth_username"] = username
params["x_auth_password"] = passwd
params["x_auth_mode"] = 'client_auth'
request = oauth.OAuthRequest.from_consumer_and_token(consumer,
                                                     http_url=access_token_url,
                                                     parameters=params)
signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
request.sign_request(signature_method, consumer, None)
headers=request_to_header(request)

resp = urlopen(Request(access_token_url, headers=headers))
token = resp.read()
print token  # 已经获得access_token

m = re.match(r'oauth_token=(?P<key>[^&]+)&oauth_token_secret=(?P<secret>[^&]+)', token)
if m:
    oauth_token = oauth.OAuthToken(m.group('key'), m.group('secret'))
    request = oauth.OAuthRequest.from_consumer_and_token(consumer,
                                                     token=oauth_token,
                                                     http_url=verify_url)
    request.sign_request(signature_method, consumer, oauth_token)
    headers=request_to_header(request)
    resp = urlopen(Request(verify_url, headers=headers))
    resp = resp.read()
    print resp

```