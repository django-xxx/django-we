# -*- coding: utf-8 -*-

from django.conf import settings
from django.shortcuts import redirect
from furl import furl
from json_response import auto_response
from pywe_jssdk import jsapi_signature_params
from pywe_oauth import get_access_info, get_oauth_code_url, get_oauth_redirect_url, get_userinfo


JSAPI = settings.WECHAT.get('JSAPI', {})


def we_oauth2(request):
    scope = request.GET.get('scope', 'snsapi_userinfo')
    redirect_url = request.GET.get('redirect_url', '')
    default_url = request.GET.get('default_url', '')

    if request.wechat:
        redirect_uri = settings.WECHAT_USERINFO_REDIRECT_URI if scope == 'snsapi_userinfo' else settings.WECHAT_BASE_REDIRECT_URI
        return redirect(get_oauth_code_url(JSAPI['appID'], redirect_uri, scope, redirect_url))

    return redirect(default_url or redirect_url)


def base_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    access_info = get_access_info(JSAPI['appID'], JSAPI['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_base', state))

    return redirect(furl(state).add(access_info).url)


def userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    access_info = get_access_info(JSAPI['appID'], JSAPI['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_userinfo', state))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_userinfo', state))

    return redirect(furl(state).add(userinfo).url)


@auto_response
def we_jsapi_signature_api(request):
    return jsapi_signature_params(JSAPI['appID'], JSAPI['appsecret'], request.GET.get('url', '') or request.POST.get('url', ''))
