# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models
from django_models_ext import BaseModelMixin, SexModelMixin
from django_six import gettext_lazy as _
from jsonfield import JSONField


class TokenRefreshLogInfo(BaseModelMixin):
    appid = models.CharField(_(u'appid'), max_length=32, blank=True, null=True, help_text=u'APPID', db_index=True)
    secret = models.CharField(_(u'secret'), max_length=32, blank=True, null=True, help_text=u'Secret')
    access_info = JSONField(_(u'access_info'), blank=True, null=True, help_text=u'Access Info')

    class Meta:
        verbose_name = _(u'tokenrefreshloginfo')
        verbose_name_plural = _(u'tokenrefreshloginfo')

    def __unicode__(self):
        return self.pk


class TicketRefreshLogInfo(BaseModelMixin):
    appid = models.CharField(_(u'appid'), max_length=32, blank=True, null=True, help_text=u'APPID', db_index=True)
    secret = models.CharField(_(u'secret'), max_length=32, blank=True, null=True, help_text=u'Secret')
    ticket_type = models.CharField(_(u'ticket_type'), max_length=8, blank=True, null=True, help_text=u'Ticket Type')
    ticket_info = JSONField(_(u'ticket_info'), blank=True, null=True, help_text=u'Ticket Info')

    class Meta:
        verbose_name = _(u'ticketrefreshloginfo')
        verbose_name_plural = _(u'ticketrefreshloginfo')

    def __unicode__(self):
        return self.pk


class ComponentTokenRefreshLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    component_access_info = JSONField(_(u'component_access_info'), blank=True, null=True, help_text=u'Component Access Info')

    class Meta:
        verbose_name = _(u'componenttokenrefreshloginfo')
        verbose_name_plural = _(u'componenttokenrefreshloginfo')

    def __unicode__(self):
        return self.pk


class ComponentAuthTokenRefreshLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    authorizer_appid = models.CharField(_(u'authorizer_appid'), max_length=32, blank=True, null=True, help_text=u'Authorizer APPID', db_index=True)
    component_authorizer_access_info = JSONField(_(u'component_authorizer_access_info'), blank=True, null=True, help_text=u'Component Authorizer Access Info')

    class Meta:
        verbose_name = _(u'componentauthtokenrefreshloginfo')
        verbose_name_plural = _(u'componentauthtokenrefreshloginfo')

    def __unicode__(self):
        return self.pk


class ComponentVerifyTicketLogInfo(BaseModelMixin):
    component_appid = models.CharField(_(u'component_appid'), max_length=32, blank=True, null=True, help_text=u'Component APPID', db_index=True)
    component_secret = models.CharField(_(u'component_secret'), max_length=32, blank=True, null=True, help_text=u'Component Secret')
    component_verify_ticket = JSONField(_(u'component_verify_ticket'), blank=True, null=True, help_text=u'Component Verify Ticket')

    class Meta:
        verbose_name = _(u'componentverifyticketloginfo')
        verbose_name_plural = _(u'componentverifyticketloginfo')

    def __unicode__(self):
        return self.pk


class SubscribeUserInfo(BaseModelMixin):
    extraid = models.CharField(_(u'extraid'), max_length=32, blank=True, null=True, help_text=u'ExtraID', db_index=True)

    # Refer：https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140839
    unionid = models.CharField(_(u'unionid'), max_length=32, blank=True, null=True, help_text=u'UnionID', db_index=True)
    openid = models.CharField(_(u'openid'), max_length=32, blank=True, null=True, help_text=u'OpenID', db_index=True)

    nickname = models.CharField(_(u'nickname'), max_length=32, blank=True, null=True, help_text=u'昵称')
    sex = models.IntegerField(_(u'sex'), choices=SexModelMixin.SEX_TUPLE, default=SexModelMixin.UNKNOWN, help_text=u'性别', db_index=True)
    headimgurl = models.URLField(_(u'headimgurl'), blank=True, null=True, help_text=u'头像')

    country = models.CharField(_(u'country'), max_length=16, blank=True, null=True, help_text=u'国家')
    province = models.CharField(_(u'province'), max_length=16, blank=True, null=True, help_text=u'省份')
    city = models.CharField(_(u'city'), max_length=16, blank=True, null=True, help_text=u'城市')

    subscribe = models.IntegerField(_(u'subscribe'), default=1, help_text=u'是否关注', db_index=True)
    subscribe_time = models.IntegerField(_(u'subscribe_time'), default=0, help_text=u'关注时间')
    subscribe_scene = models.CharField(_(u'subscribe_scene'), max_length=32, blank=True, null=True, help_text=u'关注渠道来源')

    groupid = models.IntegerField(_(u'groupid'), default=0, help_text=u'分组ID')
    tagid_list = JSONField(_(u'tagid_list'), blank=True, null=True, help_text=u'标签ID列表')

    qr_scene = models.IntegerField(_(u'qr_scene'), default=0, help_text=u'二维码扫码场景')
    qr_scene_str = models.CharField(_(u'qr_scene_str'), max_length=64, blank=True, null=True, help_text=u'二维码扫码场景描述')

    language = models.CharField(_(u'language'), max_length=8, default='zh_CN', help_text=u'语言')

    remark = models.CharField(_(u'remark'), max_length=16, blank=True, null=True, help_text=u'备注')

    class Meta:
        verbose_name = _(u'subscribeuserinfo')
        verbose_name_plural = _(u'subscribeuserinfo')

        unique_together = (
            ('extraid', 'unionid', 'openid'),
        )

    def __unicode__(self):
        return self.pk
