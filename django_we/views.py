# -*- coding: utf-8 -*-

from django.conf import settings
from django.db import transaction
from django.shortcuts import redirect, render
from furl import furl
from json_response import auto_response
from pywe_jssdk import jsapi_signature_params
from pywe_oauth import get_access_info, get_oauth_code_url, get_oauth_redirect_url, get_userinfo


JSAPI = settings.WECHAT.get(getattr(settings, 'DJANGO_WE_OAUTH_CFG') if hasattr(settings, 'DJANGO_WE_OAUTH_CFG') else 'JSAPI', {})


def we_oauth2(request):
    scope = request.GET.get('scope', 'snsapi_userinfo')
    redirect_url = request.GET.get('redirect_url', '')
    default_url = request.GET.get('default_url', '')

    if not (redirect_url or default_url):
        return render(request, 'django_we/errmsg.html', {'errmsg': 'Redirect or Default URL Should Exists'})

    if request.wechat:
        CFG = JSAPI
        if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
            CFG = settings.DJANGO_WE_CFG_FUNC(request, redirect_url) or JSAPI
        redirect_uri = settings.WECHAT_USERINFO_REDIRECT_URI if scope == 'snsapi_userinfo' else settings.WECHAT_BASE_REDIRECT_URI
        return redirect(get_oauth_code_url(CFG['appID'], redirect_uri, scope, redirect_url))

    return redirect(default_url or redirect_url)


@transaction.atomic
def base_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    CFG = JSAPI
    if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
        CFG = settings.DJANGO_WE_CFG_FUNC(request, state) or JSAPI

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_base', state))

    query_params = {}
    if hasattr(settings, 'DJANGO_WE_BASE_FUNC') and hasattr(settings.DJANGO_WE_BASE_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_BASE_FUNC(code, state, access_info)

    return redirect(furl(state).add(access_info).add(query_params).url)


@transaction.atomic
def userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    CFG = JSAPI
    if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
        CFG = settings.DJANGO_WE_CFG_FUNC(request, state) or JSAPI

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_userinfo', state))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(settings.WECHAT_OAUTH2_REDIRECT_URI, 'snsapi_userinfo', state))

    query_params = {}
    if hasattr(settings, 'DJANGO_WE_USERINFO_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_USERINFO_FUNC(code, state, access_info, userinfo)

    return redirect(furl(state).add(userinfo).add(query_params).url)


@auto_response
def we_jsapi_signature_api(request):
    CFG = JSAPI
    if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
        CFG = settings.DJANGO_WE_CFG_FUNC(request) or JSAPI
    return jsapi_signature_params(CFG['appID'], CFG['appsecret'], request.GET.get('url', '') or request.POST.get('url', ''))
