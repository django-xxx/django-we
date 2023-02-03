# django-we
Django WeChat OAuth2/Share/Token API

## Installation
```shell
pip install django-we
```

## Urls.py
```python
from django.urls import include, re_path

urlpatterns = [
    re_path(r'^we/', include('django_we.urls', namespace='django_we')),
]
```
or
```python
from django.urls import re_path
from django_we import views as we_views

# WeChat OAuth2
urlpatterns = [
    re_path(r'^o$', we_views.we_oauth2, name='shorten_o'),
    re_path(r'^oauth$', we_views.we_oauth2, name='shorten_oauth'),
    re_path(r'^oauth2$', we_views.we_oauth2, name='shorten_oauth2'),
    re_path(r'^we_oauth2$', we_views.we_oauth2, name='we_oauth2'),
    re_path(r'^base_redirect$', we_views.base_redirect, name='base_redirect'),
    re_path(r'^userinfo_redirect$', we_views.userinfo_redirect, name='userinfo_redirect'),
    re_path(r'^direct_base_redirect$', we_views.direct_base_redirect, name='direct_base_redirect'),
    re_path(r'^direct_userinfo_redirect$', we_views.direct_userinfo_redirect, name='direct_userinfo_redirect'),
]

# WeChat Share
urlpatterns += [
    re_path(r'^ws$', we_views.we_share, name='shorten_we_share'),
    re_path(r'^weshare$', we_views.we_share, name='we_share'),
]

# WeChat JSAPI Signature
urlpatterns += [
    re_path(r'^js$', we_views.we_jsapi_signature_api, name='shorten_we_jsapi_signature_api'),
    re_path(r'^jsapi_signature$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),
]

# WeChat Token
urlpatterns += [
    re_path(r'^token$', we_views.we_access_token, name='we_token'),
    re_path(r'^access_token$', we_views.we_access_token, name='we_access_token'),
]
```

## Settings.py
```python
INSTALLED_APPS = (
    ...
    'django_we',
    ...
)

# Wechat Settings
WECHAT = {
    'JSAPI': {
        'token': '5201314',
        'appID': '',
        'appsecret': '',
        'mchID': '',
        'apiKey': '',
        'mch_cert': '',
        'mch_key': '',
        'redpack': {
            'SEND_NAME': '',
            'NICK_NAME': '',
            'ACT_NAME': '',
            'WISHING': '',
            'REMARK': '',
        }
    },
}

# Wechat OAuth Cfg
DJANGO_WE_OAUTH_CFG = 'JSAPI'  # Default ``JSAPI``

# Based on Urls.py
# WECHAT_OAUTH2_REDIRECT_URI = 'https://we.com/we/we_oauth2?scope={}&redirect_url={}'
# WECHAT_OAUTH2_REDIRECT_URI = 'https://we.com/we/o?scope={}&r={}'  # Shorten URL
WECHAT_OAUTH2_REDIRECT_URI = 'https://we.com/we/o?r={}'  # Shorten URL Farther, Scope default ``snsapi_userinfo``
WECHAT_BASE_REDIRECT_URI = 'https://we.com/we/base_redirect'
WECHAT_USERINFO_REDIRECT_URI = 'https://we.com/we/userinfo_redirect'
WECHAT_DIRECT_BASE_REDIRECT_URI = 'https://we.com/we/direct_base_redirect'
WECHAT_DIRECT_USERINFO_REDIRECT_URI = 'https://we.com/we/direct_userinfo_redirect'

# Temp Share Page to Redirect
WECHAT_OAUTH2_REDIRECT_URL = ''
```

# Callbacks
* [See django_we_callback_settings.py](https://github.com/django-xxx/django-project-templet-cn/blob/master/templet/templet/django_we_callback_settings.py)

## Wechat_Only
* Settings.py
  ```python
  MIDDLEWARE = [
      ...
      'detect.middleware.UserAgentDetectionMiddleware',
      ...
  ]

  WECHAT_ONLY = True  # Default False
  ```
* Usage
  ```python
  from django_we.decorators import wechat_only

  @wechat_only
  def xxx(request):
      """ Docstring """
  ```
