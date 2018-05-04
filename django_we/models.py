# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_models_ext import BaseModelMixin
from jsonfield import JSONField


class TokenRefreshLogInfo(BaseModelMixin):
    appid = models.CharField(_(u'appid'), max_length=32, blank=True, null=True, help_text=u'APPID', db_index=True)
    secret = models.CharField(_(u'secret'), max_length=32, blank=True, null=True, help_text=u'Secret')
    access_info = JSONField(_(u'access_info'), blank=True, null=True, help_text=u'Access Info')

    class Meta:
        verbose_name = _(u'tokenrefreshloginfo')
        verbose_name_plural = _(u'tokenrefreshloginfo')

    def __unicode__(self):
        return unicode(self.pk)


class TicketRefreshLogInfo(BaseModelMixin):
    appid = models.CharField(_(u'appid'), max_length=32, blank=True, null=True, help_text=u'APPID', db_index=True)
    secret = models.CharField(_(u'secret'), max_length=32, blank=True, null=True, help_text=u'Secret')
    ticket_type = models.CharField(_(u'ticket_type'), max_length=8, blank=True, null=True, help_text=u'Ticket Type')
    ticket_info = JSONField(_(u'ticket_info'), blank=True, null=True, help_text=u'Ticket Info')

    class Meta:
        verbose_name = _(u'ticketrefreshloginfo')
        verbose_name_plural = _(u'ticketrefreshloginfo')

    def __unicode__(self):
        return unicode(self.pk)


class ComponentTokenRefreshLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    component_access_info = JSONField(_(u'component_access_info'), blank=True, null=True, help_text=u'Component Access Info')

    class Meta:
        verbose_name = _(u'componenttokenrefreshloginfo')
        verbose_name_plural = _(u'componenttokenrefreshloginfo')

    def __unicode__(self):
        return unicode(self.pk)


class ComponentAuthTokenRefreshLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    authorizer_appid = models.CharField(_(u'authorizer_appid'), max_length=32, blank=True, null=True, help_text=u'Authorizer APPID', db_index=True)
    component_authorizer_access_info = JSONField(_(u'component_authorizer_access_info'), blank=True, null=True, help_text=u'Component Authorizer Access Info')

    class Meta:
        verbose_name = _(u'componentauthtokenrefreshloginfo')
        verbose_name_plural = _(u'componentauthtokenrefreshloginfo')

    def __unicode__(self):
        return unicode(self.pk)


class ComponentVerifyTicketLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    component_verify_ticket = JSONField(_(u'component_verify_ticket'), blank=True, null=True, help_text=u'Component Verify Ticket')

    class Meta:
        verbose_name = _(u'componentverifyticketloginfo')
        verbose_name_plural = _(u'componentverifyticketloginfo')

    def __unicode__(self):
        return unicode(self.pk)
