# -*- coding: utf-8 -*-

from django.conf.urls import url
from django_we import views as we_views


# WeChat OAuth2
urlpatterns = [
    url(r'^o$', we_views.we_oauth2, name='o'),
    url(r'^oauth$', we_views.we_oauth2, name='oauth'),
    url(r'^oauth2$', we_views.we_oauth2, name='oauth2'),
    url(r'^we_oauth2$', we_views.we_oauth2, name='we_oauth2'),
    url(r'^base_redirect$', we_views.base_redirect, name='base_redirect'),
    url(r'^userinfo_redirect$', we_views.userinfo_redirect, name='userinfo_redirect'),
    url(r'^direct_base_redirect$', we_views.direct_base_redirect, name='direct_base_redirect'),
    url(r'^direct_userinfo_redirect$', we_views.direct_userinfo_redirect, name='direct_userinfo_redirect'),
]

# WeChat Share
urlpatterns += [
    url(r'^weshare$', we_views.we_share, name='we_share'),
    url(r'^jsapi_signature$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),  # JSAPI Signature
]
