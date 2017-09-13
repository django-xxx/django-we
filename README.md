# django-we
Django WeChat OAuth2/Share API

## Installation
```shell
pip install django-we
```

## Urls.py
```python
urlpatterns = [
    url(r'^we/', include('django_we.urls', namespace='wechat')),
]
```
or
```python
from django.conf.urls import include, url
from django_we import views as we_views

# WecChat OAuth2
urlpatterns = [
    url(r'^oauth2$', we_views.we_oauth2, name='we_oauth2'),
    url(r'^base_redirect$', we_views.base_redirect, name='base_redirect'),
    url(r'^userinfo_redirect$', we_views.userinfo_redirect, name='userinfo_redirect'),
    url(r'^direct_base_redirect$', we_views.direct_base_redirect, name='direct_base_redirect'),
    url(r'^direct_userinfo_redirect$', we_views.direct_userinfo_redirect, name='direct_userinfo_redirect'),
]

# WeChat Share
urlpatterns += [
    url(r'^jsapi_signature$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),
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
WECHAT_OAUTH2_REDIRECT_URI = 'https://we.com/we/we_oauth2?scope={}&redirect_url={}'
WECHAT_BASE_REDIRECT_URI = 'https://we.com/we/base_redirect'
WECHAT_USERINFO_REDIRECT_URI = 'https://we.com/we/userinfo_redirect'
WECHAT_DIRECT_BASE_REDIRECT_URI = 'https://we.com/we/direct_base_redirect'
WECHAT_DIRECT_USERINFO_REDIRECT_URI = 'https://we.com/we/direct_userinfo_redirect'
```
