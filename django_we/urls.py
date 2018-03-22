# -*- coding: utf-8 -*-

from django.conf.urls import url
from django_we import views as we_views


# WeChat OAuth2
urlpatterns = [
    url(r'^o$', we_views.we_oauth2, name='shorten_o'),
    url(r'^oauth$', we_views.we_oauth2, name='shorten_oauth'),
    url(r'^oauth2$', we_views.we_oauth2, name='shorten_oauth2'),
    url(r'^we_oauth2$', we_views.we_oauth2, name='we_oauth2'),

    url(r'^br$', we_views.base_redirect, name='shorten_base_redirect'),
    url(r'^ur$', we_views.userinfo_redirect, name='shorten_userinfo_redirect'),
    url(r'^dbr$', we_views.direct_base_redirect, name='shorten_direct_base_redirect'),
    url(r'^dur$', we_views.direct_userinfo_redirect, name='shorten_direct_userinfo_redirect'),

    url(r'^base_redirect$', we_views.base_redirect, name='base_redirect'),
    url(r'^userinfo_redirect$', we_views.userinfo_redirect, name='userinfo_redirect'),
    url(r'^direct_base_redirect$', we_views.direct_base_redirect, name='direct_base_redirect'),
    url(r'^direct_userinfo_redirect$', we_views.direct_userinfo_redirect, name='direct_userinfo_redirect'),
]

# WeChat Share
urlpatterns += [
    url(r'^ws$', we_views.we_share, name='shorten_we_share'),
    url(r'^weshare$', we_views.we_share, name='we_share'),
]

# WeChat JSAPI Signature
urlpatterns += [
    url(r'^js$', we_views.we_jsapi_signature_api, name='shorten_we_jsapi_signature_api'),
    url(r'^jsapi_signature$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),
]

# WeChat Token
urlpatterns += [
    url(r'^token$', we_views.we_access_token, name='we_token'),
    url(r'^access_token$', we_views.we_access_token, name='we_access_token'),
]

# WeChat Callback
urlpatterns += [
    url(r'^cb$', we_views.we_callback, name='shorten_we_callback'),
    url(r'^callback$', we_views.we_callback, name='we_callback'),

    url(r'^cc/(?P<appid>.+)$', we_views.we_component_callback, name='shorten_we_component_callback'),
    url(r'^component_callback/(?P<appid>.+)$', we_views.we_component_callback, name='we_component_callback'),
]
