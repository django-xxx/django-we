# -*- coding: utf-8 -*-

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django_logit import logit
from django_we.models import (ComponentAuthTokenRefreshLogInfo, ComponentTokenRefreshLogInfo,
                              ComponentVerifyTicketLogInfo, TicketRefreshLogInfo, TokenRefreshLogInfo)
from furl import furl
from json_response import auto_response
from pywe_component_authorizer_token import authorizer_access_token, initial_authorizer_access_token
from pywe_component_ticket import set_component_verify_ticket
from pywe_decrypt import msg
from pywe_jssdk import jsapi_signature_params
from pywe_oauth import get_access_info, get_oauth_code_url, get_oauth_redirect_url, get_userinfo
from pywe_qrcode import qrcode_create
from pywe_sign import check_callback_signature
from pywe_storage import RedisStorage
from pywe_token import access_token, refresh_access_token
from pywe_xml import xml_to_dict


JSAPI = settings.WECHAT.get(getattr(settings, 'DJANGO_WE_OAUTH_CFG') if hasattr(settings, 'DJANGO_WE_OAUTH_CFG') else 'JSAPI', {})


def final_cfg(request, state=None):
    CFG = JSAPI
    if hasattr(settings, 'DJANGO_WE_CFG_FUNC') and hasattr(settings.DJANGO_WE_CFG_FUNC, '__call__'):
        CFG = settings.DJANGO_WE_CFG_FUNC(request, state) or JSAPI
    return CFG


def quote_state(request, state=None):
    if hasattr(settings, 'DJANGO_WE_QUOTE_OR_NOT') and not getattr(settings, 'DJANGO_WE_QUOTE_OR_NOT'):
        return state
    if hasattr(settings, 'DJANGO_WE_QUOTE_STATE_FUNC') and hasattr(settings.DJANGO_WE_QUOTE_STATE_FUNC, '__call__'):
        state = settings.DJANGO_WE_QUOTE_STATE_FUNC(request, state)
    return state


def unquote_state(request, state=None):
    if hasattr(settings, 'DJANGO_WE_QUOTE_OR_NOT') and not getattr(settings, 'DJANGO_WE_QUOTE_OR_NOT'):
        return state
    if hasattr(settings, 'DJANGO_WE_UNQUOTE_STATE_FUNC') and hasattr(settings.DJANGO_WE_UNQUOTE_STATE_FUNC, '__call__'):
        state = settings.DJANGO_WE_UNQUOTE_STATE_FUNC(request, state)
    if not state and hasattr(settings, 'WECHAT_DEFAULT_REDIRECT_URI'):
        state = settings.WECHAT_DEFAULT_REDIRECT_URI
    return state


def final_oauth_uri(request, state=None):
    oauth_uri = hasattr(settings, 'WECHAT_OAUTH2_REDIRECT_URI') and settings.WECHAT_OAUTH2_REDIRECT_URI or ''
    if hasattr(settings, 'DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC, '__call__'):
        oauth_uri = settings.DJANGO_WE_OAUTH2_REDIRECT_URI_FUNC(request, state)
    return oauth_uri


def final_direct_userinfo_redirect_uri(request):
    redirect_uri = hasattr(settings, 'WECHAT_DIRECT_USERINFO_REDIRECT_URI') and settings.WECHAT_DIRECT_USERINFO_REDIRECT_URI or ''
    if hasattr(settings, 'DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_DIRECT_USERINFO_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_direct_base_redirect_uri(request):
    redirect_uri = hasattr(settings, 'WECHAT_DIRECT_BASE_REDIRECT_URI') and settings.WECHAT_DIRECT_BASE_REDIRECT_URI or ''
    if hasattr(settings, 'DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_DIRECT_BASE_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_userinfo_redirect_uri(request):
    redirect_uri = hasattr(settings, 'WECHAT_USERINFO_REDIRECT_URI') and settings.WECHAT_USERINFO_REDIRECT_URI or ''
    if hasattr(settings, 'DJANGO_WE_USERINFO_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_USERINFO_REDIRECT_URI_FUNC(request)
    return redirect_uri


def final_base_redirect_uri(request):
    redirect_uri = hasattr(settings, 'WECHAT_BASE_REDIRECT_URI') and settings.WECHAT_BASE_REDIRECT_URI or ''
    if hasattr(settings, 'DJANGO_WE_BASE_REDIRECT_URI_FUNC') and hasattr(settings.DJANGO_WE_BASE_REDIRECT_URI_FUNC, '__call__'):
        redirect_uri = settings.DJANGO_WE_BASE_REDIRECT_URI_FUNC(request)
    return redirect_uri


def redis_storage(request):
    r = None

    if hasattr(settings, 'WECHAT_REDIS_OBJ'):
        r = settings.WECHAT_REDIS_OBJ

    if hasattr(settings, 'DJANGO_WE_REDIS_OBJ_FUNC') and hasattr(settings.DJANGO_WE_REDIS_OBJ_FUNC, '__call__'):
        r = settings.DJANGO_WE_REDIS_OBJ_FUNC(request) or r

    return r and RedisStorage(r)


# Token/Ticket Store into Database after Fetched/Refreshed
def token_fetched_func(appid, secret, access_info):
    if not hasattr(settings, 'DJANGO_WE_TOKEN_STORE_OR_NOT') or getattr(settings, 'DJANGO_WE_TOKEN_STORE_OR_NOT'):
        TokenRefreshLogInfo.objects.create(appid=appid, secret=secret, access_info=access_info)


def ticket_fetched_func(appid, secret, ticket_type, ticket_info):
    if not hasattr(settings, 'DJANGO_WE_TICKET_STORE_OR_NOT') or getattr(settings, 'DJANGO_WE_TICKET_STORE_OR_NOT'):
        TicketRefreshLogInfo.objects.create(appid=appid, secret=secret, ticket_type=ticket_type, ticket_info=ticket_info)


def component_token_fetched_func(appid, secret, access_info):
    if not hasattr(settings, 'DJANGO_WE_COMPONENT_TOKEN_STORE_OR_NOT') or getattr(settings, 'DJANGO_WE_COMPONENT_TOKEN_STORE_OR_NOT'):
        ComponentTokenRefreshLogInfo.objects.create(component_appid=appid, component_secret=secret, component_access_info=access_info)


def component_auth_token_fetched_func(component_appid, component_secret, authorizer_appid, component_authorizer_access_info):
    if not hasattr(settings, 'DJANGO_WE_COMPONENT_AUTH_TOKEN_STORE_OR_NOT') or getattr(settings, 'DJANGO_WE_COMPONENT_AUTH_TOKEN_STORE_OR_NOT'):
        ComponentAuthTokenRefreshLogInfo.objects.create(
            component_appid=component_appid,
            component_secret=component_secret,
            authorizer_appid=authorizer_appid,
            component_authorizer_access_info=component_authorizer_access_info
        )


def component_verify_ticket_push_func(component_appid, component_secret, component_verify_ticket):
    if not hasattr(settings, 'DJANGO_WE_COMPONENT_VERIFY_TICKET_STORE_OR_NOT') or getattr(settings, 'DJANGO_WE_COMPONENT_VERIFY_TICKET_STORE_OR_NOT'):
        ComponentVerifyTicketLogInfo.objects.create(
            component_appid=component_appid,
            component_secret=component_secret,
            component_verify_ticket=component_verify_ticket
        )


def we_oauth2(request):
    scope = request.GET.get('scope', '') or request.GET.get('s', 'snsapi_userinfo')
    redirect_url = request.GET.get('redirect_url', '') or request.GET.get('r', '/')
    default_url = request.GET.get('default_url', '') or request.GET.get('d', '')
    direct_redirect = bool(request.GET.get('direct_redirect', '') or request.GET.get('dr', ''))

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
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_base', final_state))

    query_params = {}

    # Toset Cookie When ``DJANGO_WE_BASE_REDIRECT_SET_COOKIE = True``
    if hasattr(settings, 'DJANGO_WE_BASE_REDIRECT_SET_COOKIE') and getattr(settings, 'DJANGO_WE_BASE_REDIRECT_SET_COOKIE'):
        if hasattr(settings, 'DJANGO_WE_BASE_COOKIE_FUNC') and hasattr(settings.DJANGO_WE_BASE_COOKIE_FUNC, '__call__'):
            query_params, cookie_key, cookie_value = settings.DJANGO_WE_BASE_COOKIE_FUNC(code, final_state, access_info)

            response = redirect(furl(final_state).remove(access_info.keys()).add(access_info).remove(query_params.keys()).add(query_params).url)

            if hasattr(settings, 'DJANGO_WE_BASE_SET_COOKIE_FUNC') and hasattr(settings.DJANGO_WE_BASE_SET_COOKIE_FUNC, '__call__'):
                return settings.DJANGO_WE_BASE_SET_COOKIE_FUNC(code, final_state, access_info, query_params, cookie_key, cookie_value)

            max_age = hasattr(settings, 'DJANGO_WE_COOKIE_MAX_AGE') and getattr(settings, 'DJANGO_WE_COOKIE_MAX_AGE') or 30 * 24 * 60 * 60  # 30d
            cookie_salt = hasattr(settings, 'DJANGO_WE_COOKIE_SALT') and getattr(settings, 'DJANGO_WE_COOKIE_SALT') or 'djwe'  # Salt for ``set_signed_cookie``

            response.set_signed_cookie(cookie_key, cookie_value, salt=cookie_salt, **{
                'max_age': max_age,
                'httponly': True,
            })

            return response

        return render(request, 'django_we/errmsg.html', {'title': 'Error', 'errmsg': 'DJANGO_WE_BASE_COOKIE_FUNC Should Exists'})

    if hasattr(settings, 'DJANGO_WE_BASE_FUNC') and hasattr(settings.DJANGO_WE_BASE_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_BASE_FUNC(code, final_state, access_info) or {}

    return redirect(furl(final_state).remove(access_info.keys()).add(access_info).remove(query_params.keys()).add(query_params).url)


@transaction.atomic
def userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_userinfo', final_state))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_userinfo', final_state))

    query_params = {}

    # Toset Cookie When ``DJANGO_WE_USERINFO_REDIRECT_SET_COOKIE = True``
    if hasattr(settings, 'DJANGO_WE_USERINFO_REDIRECT_SET_COOKIE') and getattr(settings, 'DJANGO_WE_USERINFO_REDIRECT_SET_COOKIE'):
        if hasattr(settings, 'DJANGO_WE_USERINFO_COOKIE_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_COOKIE_FUNC, '__call__'):
            query_params, cookie_key, cookie_value = settings.DJANGO_WE_USERINFO_COOKIE_FUNC(code, final_state, access_info, userinfo) or {}

            response = redirect(furl(final_state).remove(userinfo.keys()).add(userinfo).remove(query_params.keys()).add(query_params).url)

            if hasattr(settings, 'DJANGO_WE_USERINFO_SET_COOKIE_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_SET_COOKIE_FUNC, '__call__'):
                return settings.DJANGO_WE_USERINFO_SET_COOKIE_FUNC(code, final_state, access_info, userinfo, query_params, cookie_key, cookie_value)

            max_age = hasattr(settings, 'DJANGO_WE_COOKIE_MAX_AGE') and getattr(settings, 'DJANGO_WE_COOKIE_MAX_AGE') or 30 * 24 * 60 * 60  # 30d
            cookie_salt = hasattr(settings, 'DJANGO_WE_COOKIE_SALT') and getattr(settings, 'DJANGO_WE_COOKIE_SALT') or 'djwe'  # Salt for ``set_signed_cookie``

            response.set_signed_cookie(cookie_key, cookie_value, salt=cookie_salt, **{
                'max_age': max_age,
                'httponly': True,
            })

            return response

        return render(request, 'django_we/errmsg.html', {'title': 'Error', 'errmsg': 'DJANGO_WE_USERINFO_COOKIE_FUNC Should Exists'})

    if hasattr(settings, 'DJANGO_WE_USERINFO_FUNC') and hasattr(settings.DJANGO_WE_USERINFO_FUNC, '__call__'):
        query_params = settings.DJANGO_WE_USERINFO_FUNC(code, final_state, access_info, userinfo) or {}

    return redirect(furl(final_state).remove(userinfo.keys()).add(userinfo).remove(query_params.keys()).add(query_params).url)


def direct_base_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_base', final_state, direct_redirect=True))

    return redirect(furl(final_state).remove(access_info.keys()).add(access_info).url)


def direct_userinfo_redirect(request):
    code = request.GET.get('code', '')
    state = request.GET.get('state', '')

    final_state = unquote_state(request, state)

    CFG = final_cfg(request, final_state)

    access_info = get_access_info(CFG['appID'], CFG['appsecret'], code)
    if 'errcode' in access_info:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_userinfo', final_state, direct_redirect=True))

    userinfo = get_userinfo(access_info.get('access_token', ''), access_info.get('openid', ''))
    if 'openid' not in userinfo:
        return redirect(get_oauth_redirect_url(final_oauth_uri(request, final_state), 'snsapi_userinfo', final_state, direct_redirect=True))

    return redirect(furl(final_state).remove(userinfo.keys()).add(userinfo).url)


def we_share(request):
    redirect_url = ''

    if hasattr(settings, 'WECHAT_OAUTH2_REDIRECT_URL'):
        redirect_url = settings.WECHAT_OAUTH2_REDIRECT_URL

    if hasattr(settings, 'DJANGO_WE_SHARE_FUNC') and hasattr(settings.DJANGO_WE_SHARE_FUNC, '__call__'):
        redirect_url = settings.DJANGO_WE_SHARE_FUNC(request) or redirect_url

    if not redirect_url:
        return render(request, 'django_we/errmsg.html', {'title': 'Error', 'errmsg': 'Redirect URL Should Exists'})

    return redirect(redirect_url)


@auto_response
def we_jsapi_signature_api(request, state=None):
    if hasattr(settings, 'DJANGO_WE_ENABLED_OR_NOT') and not getattr(settings, 'DJANGO_WE_ENABLED_OR_NOT'):
        return {}
    CFG = final_cfg(request, state=state or 'jsapi_signature')
    return jsapi_signature_params(
        CFG['appID'],
        CFG['appsecret'],
        request.GET.get('url', '') or request.POST.get('url', ''),
        storage=redis_storage(request),
        token_fetched_func=token_fetched_func,
        ticket_fetched_func=ticket_fetched_func
    )


@auto_response
def we_access_token(request, state=None):
    fetch_type = request.GET.get('fetch_type', '')

    if fetch_type == 'refresh':
        fetch_func = refresh_access_token
    else:
        fetch_func = access_token

    CFG = final_cfg(request, state=state or 'access_token')

    return {
        'appid': CFG['appID'],
        'access_token': fetch_func(
            CFG['appID'],
            CFG['appsecret'],
            storage=redis_storage(request),
            token_fetched_func=token_fetched_func
        ),
    }


@transaction.atomic
@logit(body=True, res=True)
def we_callback(request):
    signature = request.GET.get('signature', '')
    timestamp = request.GET.get('timestamp', '')
    nonce = request.GET.get('nonce', '')
    echostr = request.GET.get('echostr', '')
    encrypt_type = request.GET.get('encrypt_type', '')
    msg_signature = request.GET.get('msg_signature', '')

    CFG = final_cfg(request, state='callback')

    # 校验签名
    if not check_callback_signature(CFG['token'], signature, timestamp, nonce):
        return HttpResponse()

    if request.method == 'GET':
        return HttpResponse(echostr)

    xml = request.body

    resp_xml = ''
    if hasattr(settings, 'DJANGO_WE_MESSAGE_CALLBACK_FUNC') and hasattr(settings.DJANGO_WE_MESSAGE_CALLBACK_FUNC, '__call__'):
        decrypted = msg.decrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], post_data=xml, encrypt=None, msg_signature=msg_signature, timestamp=timestamp, nonce=nonce, xmltodict=True)
        resp_xml = settings.DJANGO_WE_MESSAGE_CALLBACK_FUNC(request, xml_to_dict(xml), decrypted or {}) or ''

    if resp_xml:
        resp_xml = msg.encrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], resp_xml=resp_xml, nonce=nonce, timestamp=None, random_str=None)

    return HttpResponse(resp_xml or 'success')


@transaction.atomic
@logit(body=True, res=True)
def we_component_auth(request):
    signature = request.GET.get('signature', '')
    timestamp = request.GET.get('timestamp', '')
    nonce = request.GET.get('nonce', '')
    encrypt_type = request.GET.get('encrypt_type', '')
    msg_signature = request.GET.get('msg_signature', '')

    CFG = final_cfg(request, state='component_auth')

    # 校验签名
    if not check_callback_signature(CFG['token'], signature, timestamp, nonce):
        return HttpResponse()

    xml = request.body

    # 消息解密
    decrypted = msg.decrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], post_data=xml, encrypt=None, msg_signature=msg_signature, timestamp=timestamp, nonce=nonce, xmltodict=True)

    # 获取 InfoType
    InfoType = decrypted.get('InfoType', '')  # unauthorized是取消授权，updateauthorized是更新授权，authorized是授权成功通知，component_verify_ticket

    # 当 InfoType 为 component_verify_ticket 时，进行保存 component_verify_ticket 的操作
    if InfoType == 'component_verify_ticket':
        # Set Component Verify Ticket into Redis
        set_component_verify_ticket(
            appid=CFG['appID'],
            secret=CFG['appsecret'],
            token=CFG['token'],
            encodingaeskey=CFG['encodingaeskey'],
            post_data=xml,
            encrypt=None,
            msg_signature=msg_signature,
            timestamp=timestamp,
            nonce=nonce,
            storage=redis_storage(request),
        )

        # Set Component Verify Ticket into MySQL
        component_verify_ticket_push_func(CFG['appID'], CFG['appsecret'], decrypted)

    resp_xml = ''
    if hasattr(settings, 'DJANGO_WE_COMPONENT_AUTH_FUNC') and hasattr(settings.DJANGO_WE_COMPONENT_AUTH_FUNC, '__call__'):
        resp_xml = settings.DJANGO_WE_COMPONENT_AUTH_FUNC(request, xml_to_dict(xml), decrypted or {}) or ''

    if resp_xml:
        resp_xml = msg.encrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], resp_xml=resp_xml, nonce=nonce, timestamp=None, random_str=None)

    return HttpResponse(resp_xml or 'success')


@transaction.atomic
@logit(body=True, res=True)
def we_component_callback(request, appid=None):
    signature = request.GET.get('signature', '')
    timestamp = request.GET.get('timestamp', '')
    nonce = request.GET.get('nonce', '')
    encrypt_type = request.GET.get('encrypt_type', '')
    msg_signature = request.GET.get('msg_signature', '')

    CFG = final_cfg(request, state='component_callback')

    # 校验签名
    if not check_callback_signature(CFG['token'], signature, timestamp, nonce):
        return HttpResponse()

    xml = request.body

    resp_xml = ''
    if hasattr(settings, 'DJANGO_WE_COMPONENT_CALLBACK_FUNC') and hasattr(settings.DJANGO_WE_COMPONENT_CALLBACK_FUNC, '__call__'):
        decrypted = msg.decrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], post_data=xml, encrypt=None, msg_signature=msg_signature, timestamp=timestamp, nonce=nonce, xmltodict=True)
        resp_xml = settings.DJANGO_WE_COMPONENT_CALLBACK_FUNC(request, appid, xml_to_dict(xml), decrypted or {}) or ''

    if resp_xml:
        resp_xml = msg.encrypt(CFG['appID'], token=CFG['token'], encodingaeskey=CFG['encodingaeskey'], resp_xml=resp_xml, nonce=nonce, timestamp=None, random_str=None)

    return HttpResponse(resp_xml or 'success')


@logit(body=True, res=True)
def we_component_preauth_callback(request):
    auth_code = request.GET.get('auth_code', '')

    CFG = final_cfg(request, state='component_preauth_callback')

    authorizer_access_token, authorizer_appid = initial_authorizer_access_token(
        component_appid=CFG['appID'],
        component_secret=CFG['appsecret'],
        auth_code=auth_code,
        storage=redis_storage(request),
        token_fetched_func=component_token_fetched_func,
        auth_token_fetched_func=component_auth_token_fetched_func,
        with_authorizer_appid=True
    )

    if hasattr(settings, 'DJANGO_WE_COMPONENT_CALLBACK_TEMPLATE'):
        redirect_tpl = settings.DJANGO_WE_COMPONENT_CALLBACK_TEMPLATE
        if redirect_tpl:
            return render(request, redirect_tpl, {'authorizer_appid': authorizer_appid})

    return render(request, 'django_we/errmsg.html', {'title': 'Success', 'errmsg': 'Component Auth Success'})


@auto_response
def we_qrcode_url(request, state=None):
    authorizer_appid = request.GET.get('authorizer_appid', '')
    action_name = request.GET.get('action_name', 'QR_SCENE')
    scene_id = int(request.GET.get('scene_id', 0))
    scene_str = request.GET.get('scene_str', '')
    expire_seconds = int(request.GET.get('expire_seconds', 2592000))

    CFG = final_cfg(request, state=state or 'qrcode_url')

    if state == 'component':
        token = authorizer_access_token(
            component_appid=CFG['appID'],
            component_secret=CFG['appsecret'],
            authorizer_appid=authorizer_appid,
            storage=redis_storage(request),
            token_fetched_func=component_token_fetched_func,
            auth_token_fetched_func=component_auth_token_fetched_func
        )
    else:
        token = access_token(
            CFG['appID'],
            CFG['appsecret'],
            storage=redis_storage(request),
            token_fetched_func=token_fetched_func
        )

    return {
        'qrinfo': qrcode_create(
            action_name=action_name,
            scene_id=scene_id,
            scene_str=scene_str,
            expire_seconds=expire_seconds,
            appid=CFG['appID'],
            secret=CFG['appsecret'],
            token=token,
            storage=redis_storage(request)
        ),
    }
