"""MIT License.

Copyright (c) 2017 Code for Africa - LABS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


# coding=utf-8
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import json
import ckan.lib.helpers as helpers
import requests
import re
import logging

from ckan.common import g, request, response, config, session

# get 'ckan.googleauth_clientid' from ini file
def get_google_clientid():
    """Extract Client ID from config(.ini) file."""
    return config.get('ckan.googleauth_clientid', '')


# get ckan.googleauth_hosted_domain from ini file
def get_hosted_domain():
    """Extract Hosted Domain from config(.ini) file."""
    return config.get('ckan.googleauth_hosted_domain', '')


class AuthException(Exception):
    """Exception to be raised for errors."""

    pass


class SocialitePlugin(plugins.SingletonPlugin):
    """Set up plugin for CKAN integration."""

    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IRoutes, inherit=True)

    def update_config(self, config_):
        """Add resources used by the plugin into core config file."""
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'googleauth')

    def before_map(self, map):
        """
        Override IRoutes.before_map()
        """
        controller = 'ckanext.socialite.controller:UserFirebaseController'
        map.connect('firebaseLogin',
                    "/firebase/login",
                    controller=controller,
                    action='login')
        map.connect('firebaseLogout',
                    "/firebase/logout",
                    controller=controller,
                    action='logout')
        return map

    def get_helpers(self):
        """Declare new helper functions."""
        return {'googleauth_get_clientid': get_google_clientid,
                'googleauth_get_hosted_domain': get_hosted_domain}


    def login(self):
       pass


    # if someone is logged in will be set the parameter c.user
    def identify(self):
        """Logged in CKAN user will be set as c.user parameter."""
        user_ckan = session.get('ckanext_user')
        if user_ckan:
            toolkit.c.user = user_ckan

    def logout(self):
        """Call _logout_user()."""
        self._logout_user()

    def abort(self):
        """In case of any errors, calls _logout_user()."""
        self._logout_user()
