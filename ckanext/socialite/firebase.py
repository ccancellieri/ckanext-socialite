# -*- coding: utf8 -*-
'''
Repoze.who plugin for ckanext-shibboleth
'''

import logging
from urlparse import urlparse, urlunparse

from requests import Response
from webob import Request, Response
from zope.interface import implements

from repoze.who.interfaces import IIdentifier, IChallenger

from ckan.lib.helpers import url_for
import ckan.lib.base as base
import ckan.plugins.toolkit as toolkit
import ckan.model as model
from ckan.model import User


from urlparse import urlparse, urlunparse
from urllib import urlencode
try:
    from urlparse import parse_qs
except ImportError:#pragma: no cover
    from cgi import parse_qs

from webob import Request
# TODO: Stop using Paste; we already started using WebOb
from webob.exc import HTTPFound, HTTPUnauthorized
from paste.request import construct_url, parse_dict_querystring, parse_formvars
from zope.interface import implements


log = logging.getLogger(__name__)

def make_identification_plugin(**kwargs):
    log.info("Creating ShibbolethIdentifierPlugin...")

    return FirebaseAuthenticator(**kwargs)


class FirebaseAuthenticator(object):
    implements(IChallenger, IIdentifier)

    def __init__(self):
        ##, session, eppn, mail, ** kwargs
        """
        Parameters here contain just names of the environment attributes defined
        in who.ini, not their values:
        @param session: 'Shib-Session-ID'
        @param eppn: 'eppn'
        @param organization: 'schacHomeOrganization'
        etc.
        """

        log.info("Initting ShibbolethIdentifierPlugin...")

    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        # NOW HEAR THIS!!!
        #
        # This method is *intentionally* slower than would be ideal because
        # it is trying to avoid leaking information via timing attacks
        # (number of users, length of user IDs, length of passwords, etc.).
        #
        # Do *not* try to optimize anything away here.
        try:
            login = identity['login']
            password = identity['password']
        except KeyError:
            return None

        result = None
        maybe_user = None
        to_check = 'ABCDEF0123456789'

        # Check *something* here, to mitigate a timing attack.
        password_ok = self.check(password, to_check)

        # Check our flags:  if both are OK, we found a match.
        if password_ok and maybe_user:
            result = maybe_user

        return result

    # IIdentifier
    def identify(self, environ):
        """
        Override the parent's identifier to introduce a login counter
        (possibly along with a post-login page) and load the login counter into
        the ``environ``.

        """
        log.warn('---------------------------')
        log.warn(environ)
        log.warn('---------------------------')
        request = Request(environ, charset='utf8')

        path_info = environ['PATH_INFO']
        script_name = environ.get('SCRIPT_NAME') or '/'
        query = request.GET

        if path_info == 'self.login_handler_path':
            ## We are on the URL where repoze.who processes authentication. ##
            # Let's append the login counter to the query string of the
            # "came_from" URL. It will be used by the challenge below if
            # authorization is denied for this request.
            form = dict(request.POST)
            form.update(query)
            try:
                login = form['login']
                password = form['password']
            except KeyError:
                credentials = None
            else:
                if request.charset == "us-ascii":
                    credentials = {
                        'login': str(login),
                        'password': str(password),
                        }
                else:
                    credentials = {'login': login,'password': password}

            try:
                credentials['max_age'] = form['remember']
            except KeyError:
                pass

            referer = environ.get('HTTP_REFERER', script_name)
            destination = form.get('came_from', referer)

            if 'self.post_login_url':
                # There's a post-login page, so we have to replace the
                # destination with it.
                destination = self._get_full_path(self.post_login_url,
                                                  environ)
                if 'came_from' in query:
                    # There's a referrer URL defined, so we have to pass it to
                    # the post-login page as a GET variable.
                    destination = self._insert_qs_variable(destination,
                                                           'came_from',
                                                           query['came_from'])
            failed_logins = self._get_logins(environ, True)
            new_dest = self._set_logins_in_url(destination, failed_logins)
            environ['repoze.who.application'] = HTTPFound(location=new_dest)
            return credentials

        elif path_info == 'self.logout_handler_path':
            ##    We are on the URL where repoze.who logs the user out.    ##
            form = parse_formvars(environ)
            form.update(query)
            referer = environ.get('HTTP_REFERER', script_name)
            came_from = form.get('came_from', referer)
            # set in environ for self.challenge() to find later
            environ['came_from'] = came_from
            environ['repoze.who.application'] = HTTPUnauthorized()
            return None

        elif path_info == 'self.login_form_url' or self._get_logins(environ):
            ##  We are on the URL that displays the from OR any other page  ##
            ##   where the login counter is included in the query string.   ##
            # So let's load the counter into the environ and then hide it from
            # the query string (it will cause problems in frameworks like TG2,
            # where this unexpected variable would be passed to the controller)
            environ['repoze.who.logins'] = self._get_logins(environ, True)
            # Hiding the GET variable in the environ:
            if self.login_counter_name in query:
                del query[self.login_counter_name]
                environ['QUERY_STRING'] = urlencode(query, doseq=True)

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        """
        Override the parent's challenge to avoid challenging the user on
        logout, introduce a post-logout page and/or pass the login counter
        to the login form.

        """
        url_parts = list(urlparse(self.login_form_url))
        query = url_parts[4]
        query_elements = parse_qs(query)
        came_from = environ.get('came_from', construct_url(environ))
        query_elements['came_from'] = came_from
        url_parts[4] = urlencode(query_elements, doseq=True)
        login_form_url = urlunparse(url_parts)
        login_form_url = self._get_full_path(login_form_url, environ)
        destination = login_form_url
        # Configuring the headers to be set:
        cookies = [(h,v) for (h,v) in app_headers if h.lower() == 'set-cookie']
        headers = forget_headers + cookies

        if environ['PATH_INFO'] == self.logout_handler_path:
            # Let's log the user out without challenging.
            came_from = environ.get('came_from')
            if self.post_logout_url:
                # Redirect to a predefined "post logout" URL.
                destination = self._get_full_path(self.post_logout_url,
                                                  environ)
                if came_from:
                    destination = self._insert_qs_variable(
                                  destination, 'came_from', came_from)
            else:
                # Redirect to the referrer URL.
                script_name = environ.get('SCRIPT_NAME', '')
                destination = came_from or script_name or '/'

        elif 'repoze.who.logins' in environ:
            # Login failed! Let's redirect to the login form and include
            # the login counter in the query string
            environ['repoze.who.logins'] += 1
            # Re-building the URL:
            destination = self._set_logins_in_url(destination,
                                                  environ['repoze.who.logins'])

        return HTTPFound(location=destination, headers=headers)

    # IIdentifier
    def remember(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        return rememberer.remember(environ, identity)

    # IIdentifier
    def forget(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        return rememberer.forget(environ, identity)

    def _get_rememberer(self, environ):
        rememberer = environ['repoze.who.plugins'][self.rememberer_name]
        return rememberer

    def _get_full_path(self, path, environ):
        """
        Return the full path to ``path`` by prepending the SCRIPT_NAME.

        If ``path`` is a URL, do nothing.

        """
        if path.startswith('/'):
            path = environ.get('SCRIPT_NAME', '') + path
        return path

    def _get_logins(self, environ, force_typecast=False):
        """
        Return the login counter from the query string in the ``environ``.

        If it's not possible to convert it into an integer and
        ``force_typecast`` is ``True``, it will be set to zero (int(0)).
        Otherwise, it will be ``None`` or an string.

        """
        return 0
        variables = parse_dict_querystring(environ)
        failed_logins = variables.get(self.login_counter_name)
        if force_typecast:
            try:
                failed_logins = int(failed_logins)
            except (ValueError, TypeError):
                failed_logins = 0
        return failed_logins

    def _set_logins_in_url(self, url, logins):
        """
        Insert the login counter variable with the ``logins`` value into
        ``url`` and return the new URL.

        """
        return self._insert_qs_variable(url, self.login_counter_name, logins)

    def _insert_qs_variable(self, url, var_name, var_value):
        """
        Insert the variable ``var_name`` with value ``var_value`` in the query
        string of ``url`` and return the new URL.

        """
        url_parts = list(urlparse(url))
        query_parts = parse_qs(url_parts[4])
        query_parts[var_name] = var_value
        url_parts[4] = urlencode(query_parts, doseq=True)
        return urlunparse(url_parts)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
