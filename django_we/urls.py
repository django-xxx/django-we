# -*- coding: utf-8 -*-

from django_six import re_path

from django_we import views as we_views


app_name = 'django_we'


# WeChat OAuth2
urlpatterns = [
    re_path(r'^o$', we_views.we_oauth2, name='shorten_o'),
    re_path(r'^oauth$', we_views.we_oauth2, name='shorten_oauth'),
    re_path(r'^oauth2$', we_views.we_oauth2, name='shorten_oauth2'),
    re_path(r'^we_oauth2$', we_views.we_oauth2, name='we_oauth2'),

    re_path(r'^br$', we_views.base_redirect, name='shorten_base_redirect'),
    re_path(r'^ur$', we_views.userinfo_redirect, name='shorten_userinfo_redirect'),
    re_path(r'^dbr$', we_views.direct_base_redirect, name='shorten_direct_base_redirect'),
    re_path(r'^dur$', we_views.direct_userinfo_redirect, name='shorten_direct_userinfo_redirect'),

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
    re_path(r'^js/(?P<state>.*)$', we_views.we_jsapi_signature_api, name='shorten_we_jsapi_signature_api'),
    re_path(r'^jsapi_signature/(?P<state>.*)$', we_views.we_jsapi_signature_api, name='we_jsapi_signature_api'),
]

# WeChat Token
urlpatterns += [
    re_path(r'^token/(?P<state>.*)$', we_views.we_access_token, name='we_token'),
    re_path(r'^access_token/(?P<state>.*)$', we_views.we_access_token, name='we_access_token'),
]

# WeChat Callback
urlpatterns += [
    # 公众号（订阅号/服务号）
    # 服务器地址(URL)
    # 必须以http://或https://开头，分别支持80端口和443端口。
    re_path(r'^cb$', we_views.we_callback, name='shorten_we_callback'),
    re_path(r'^callback$', we_views.we_callback, name='we_callback'),
]

# WeChat Component Callback
urlpatterns += [
    # 第三方平台
    # 授权事件接收URL
    # 用于接收取消授权通知、授权成功通知、授权更新通知，也用于接收ticket，ticket是验证平台方的重要凭据。
    re_path(r'^ca$', we_views.we_component_auth, name='shorten_we_component_auth'),
    re_path(r'^component_auth$', we_views.we_component_auth, name='we_component_auth'),

    # 第三方平台
    # 消息与事件接收URL
    # 通过该URL接收公众号或小程序消息和事件推送，该参数按规则填写（需包含/$APPID$，如www.abc.com/$APPID$/callback），实际接收消息时$APPID$将被替换为公众号或小程序AppId。
    re_path(r'^cc/(?P<appid>.+)$', we_views.we_component_callback, name='shorten_we_component_callback'),
    re_path(r'^component_callback/(?P<appid>.+)$', we_views.we_component_callback, name='we_component_callback'),

    # https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=&lang=zh_CN
    # 步骤4：授权后回调URI，得到授权码（authorization_code）和过期时间
    # 授权流程完成后，授权页会自动跳转进入回调URI，并在URL参数中返回授权码和过期时间(redirect_url?auth_code=xxx&expires_in=600)
    re_path(r'^cp$', we_views.we_component_preauth_callback, name='shorten_we_component_preauth_callback'),
    re_path(r'^component_preauth$', we_views.we_component_preauth_callback, name='we_component_preauth_callback'),
]

# WeChat Common/Component APIs
urlpatterns += [
    re_path(r'^qrurl/(?P<state>.*)$', we_views.we_qrcode_url, name='we_qrcode_url'),
]
