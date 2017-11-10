# -*- coding: utf-8 -*-

from django.conf import settings
from django.db import transaction
from django.shortcuts import redirect, render
from furl import furl
from json_response import auto_response
from pywe_jssdk import jsapi_signature_params
from pywe_oauth import get_access_info, get_oauth_code_url, get_oauth_redirect_url, get_userinfo
from pywe_token import access_token


JSAPI = settings.WECHAT.get(getattr(settings, 'DJANGO_WE_OAUTH_CFG') if hasattr(settings, 'DJANGO_WE_OAUTH_CFG') else 'JSAPI', {})


def final_cfg(request, state=None):
    CFG = JSAPI
    if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
        CFG = settings.DJANGO_WE_CFG_FUNC(request, state) or JSAPI
    return CFG


def quote_state(request, state=None):
    if hasattr(settings, 'DJANGO_WE_QUOTE_STATE_FUNC') and hasattr(settings.DJANGO_WE_QUOTE_STATE_FUNC, '__call__'):
        state = settings.DJANGO_WE_QUOTE_STATE_FUNC(request, state)
    return state


def unquote_state(request, state=None):
    if hasattr(settings, 'DJANGO_WE_UNQUOTE_STATE_FUNC') and hasattr(settings.DJANGO_WE_UNQUOTE_STATE_FUNC, '__call__'):
        state = settings.DJANGO_WE_UNQUOTE_STATE_FUNC(request, state)
    return state


def final_oauth_uri(request, state=None):
    oauth_uri = settings.WECHAT_OAUTH2_REDIRECT_URI
    if hasattr(settings, 'DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC, '__call__'):
        oauth_uri = settings.DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC(request, state)
    return oauth_uri


def final_direct_userinfo_redirect_uri(request):
    redirect_uri = settings.WECHAT_DIRECT_USERINFO_REDIRECT_URI
    if hasattr(settings, 'DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_direct_base_redirect_uri(request):
    redirect_uri = settings.WECHAT_DIRECT_BASE_REDIRECT_URI
    if hasattr(settings, 'DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_userinfo_redirect_uri(request):
    redirect_uri = settings.WECHAT_USERINFO_REDIRECT_URI
    if hasattr(settings, 'DJANGO_WE_USERINFO_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_USERINFO_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_base_redirect_uri(request):
    redirect_uri = settings.WECHAT_BASE_REDIRECT_URI
    if hasattr(settings, 'DJANGO_WE_BASE_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_BASE_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_BASE_REDIRECT_URI_FUNC(request)
    return redirect_uri


def we_oauth2(request):
    scope = request.GET.get('scope', 'snsapi_userinfo')
    redirect_url = request.GET.get('redirect_url', '')
    default_url = request.GET.get('default_url', '')
    direct_redirect = bool(request.GET.get('direct_redirect', ''))

    if not (redirect_url or default_url):
        return render(request, 'django_we/errmsg.html', {'title': 'Error', 'errmsg': 'Redirect or Default URL Should Exists'})

    if request.wechat:
        CFG = final_cfg(request, redirect_url)
        if direct_redirect:
            redirect_uri = final_direct_userinfo_redirect_uri(request) if scope == 'snsapi_userinfo' else final_direct_base_redirect_uri(request)
        else:
            redirect_uri = final_userinfo_redirect_uri(request) if scope == 'snsapi_userinfo' else final_base_redirect_uri(request)
        return redirect(get_oauth_code_url(CFG['appID'], redirect_uri, scope, quote_state(request, redirect_url)))

    return redirect(default_url or redirect_url)


@transaction.atomic
def base_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_base', state))

    query_params = {}
    if hasattr(settings, 'DJANGO_WE_BASE_FUNC') and hasattr(settings.DJANGO_WE_BASE_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_BASE_FUNC(code, final_state, access_info)

    return redirect(furl(final_state).add(access_info).add(query_params).url)


@transaction.atomic
def userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_userinfo', state))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_userinfo', state))

    query_params = {}
    if hasattr(settings, 'DJANGO_WE_USERINFO_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_USERINFO_FUNC(code, final_state, access_info, userinfo)

    return redirect(furl(final_state).add(userinfo).add(query_params).url)


def direct_base_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_base', state, direct_redirect=True))

    return redirect(furl(final_state).add(access_info).url)


def direct_userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_userinfo', state, direct_redirect=True))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, state), 'snsapi_userinfo', state, direct_redirect=True))

    return redirect(furl(final_state).add(userinfo).url)


def we_share(request):
    redirect_url = ''

    if hasattr(settings, 'WECHAT_OAUTH2_REDIRECT_URL'):
        redirect_url = settings.WECHAT_OAUTH2_REDIRECT_URL

    if hasattr(settings, 'DJANGO_WE_SHARE_FUNC') and hasattr(settings.DJANGO_WE_SHARE_FUNC, '__call__'):
        redirect_url = settings.DJANGO_WE_SHARE_FUNC(request)

    if not redirect_url:
        return render(request, 'django_we/errmsg.html', {'title': 'Error', 'errmsg': 'Redirect URL Should Exists'})

    return redirect(redirect_url)


@auto_response
def we_jsapi_signature_api(request):
    CFG = final_cfg(request)
    return jsapi_signature_params(CFG['appID'], CFG['appsecret'], request.GET.get('url', '') or request.POST.get('url', ''))


@auto_response
def we_access_token(request):
    CFG = final_cfg(request)
    return {
        'access_token': access_token(CFG['appID'], CFG['appsecret']),
    }
