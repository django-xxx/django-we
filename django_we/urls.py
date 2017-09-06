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
]

# WeChat Share
urlpatterns += [
    url(r'^jsapi_signature$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),  # JSAPI Signature
]
