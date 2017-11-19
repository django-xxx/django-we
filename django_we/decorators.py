# -*- coding: utf-8 -*-

from functools import wraps

from django.conf import settings
from django.shortcuts import render


def wechat_only(func=None):
    def decorator(func):
        @wraps(func)
        def returned_wrapper(request, *args, **kwargs):
            if not settings.DEBUG and hasattr(request, 'wechat') and getattr(request, 'wechat'):
                if not (hasattr(request, 'WECHAT_ONLY') and not getattr(request, 'WECHAT_ONLY')):
                    return render(request, 'django_we/errmsg.html', {'title': '错误', 'errmsg': '请在微信中打开'})
            return func(request, *args, **kwargs)
        return returned_wrapper

    if not func:
        def foo(func):
            return decorator(func)
        return foo

    return decorator(func)
