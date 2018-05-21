# -*- coding: utf-8 -*-

from setuptools import setup


version = '1.4.0'


setup(
    name='django-we',
    version=version,
    keywords='django-we',
    description='Django WeChat OAuth2/Share/Token API',
    long_description=open('README.rst').read(),

    url='https://github.com/django-xxx/django-we',

    author='Hackathon',
    author_email='kimi.huang@brightcells.com',

    packages=['django_we'],
    py_modules=[],
    install_requires=['django-admin>=1.2.4', 'django-detect', 'django-json-response', 'django-logit', 'django-models-ext', 'furl', 'jsonfield', 'pywe-component-authorizer-token>=1.1.1', 'pywe-component-ticket', 'pywe-decrypt>=1.1.3', 'pywe-jssdk>=1.1.0', 'pywe-oauth>=1.0.5', 'pywe-qrcode', 'pywe-sign>=1.0.7', 'pywe-storage', 'pywe-token>=1.2.1', 'pywe-xml'],
    include_package_data=True,

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Office/Business :: Financial :: Spreadsheet',
    ],
)
