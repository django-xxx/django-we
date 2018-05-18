# -*- coding: utf-8 -*-

from django.conf import settings
from django.contrib import admin
from django_admin import ReadOnlyModelAdmin
from django_we.models import (ComponentAuthTokenRefreshLogInfo, ComponentTokenRefreshLogInfo,
                              ComponentVerifyTicketLogInfo, TicketRefreshLogInfo, TokenRefreshLogInfo)


class TokenRefreshLogInfoAdmin(ReadOnlyModelAdmin, admin.ModelAdmin):
    list_display = ('appid', 'secret', 'access_info', 'status', 'created_at', 'updated_at')
    list_filter = ('appid', 'status')


class TicketRefreshLogInfoAdmin(ReadOnlyModelAdmin, admin.ModelAdmin):
    list_display = ('appid', 'secret', 'ticket_type', 'ticket_info', 'status', 'created_at', 'updated_at')
    list_filter = ('appid', 'ticket_type', 'status')


class ComponentTokenRefreshLogInfoAdmin(ReadOnlyModelAdmin, admin.ModelAdmin):
    list_display = ('component_appid', 'component_secret', 'component_access_info', 'status', 'created_at', 'updated_at')
    list_filter = ('component_appid', 'status')


class ComponentAuthTokenRefreshLogInfoAdmin(ReadOnlyModelAdmin, admin.ModelAdmin):
    list_display = ('component_appid', 'component_secret', 'authorizer_appid', 'component_authorizer_access_info', 'status', 'created_at', 'updated_at')
    list_filter = ('component_appid', 'authorizer_appid', 'status')


class ComponentVerifyTicketLogInfoAdmin(ReadOnlyModelAdmin, admin.ModelAdmin):
    list_display = ('component_appid', 'component_secret', 'component_verify_ticket', 'status', 'created_at', 'updated_at')
    list_filter = ('component_appid', 'status')


if not hasattr(settings, 'DJANGO_WE_MODEL_DISPLAY_OR_NOT') or getattr(settings, 'DJANGO_WE_MODEL_DISPLAY_OR_NOT'):
    admin.site.register(TokenRefreshLogInfo, TokenRefreshLogInfoAdmin)
    admin.site.register(TicketRefreshLogInfo, TicketRefreshLogInfoAdmin)
    admin.site.register(ComponentTokenRefreshLogInfo, ComponentTokenRefreshLogInfoAdmin)
    admin.site.register(ComponentAuthTokenRefreshLogInfo, ComponentAuthTokenRefreshLogInfoAdmin)
    admin.site.register(ComponentVerifyTicketLogInfo, ComponentVerifyTicketLogInfoAdmin)
