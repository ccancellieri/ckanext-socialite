'''
Repoze.who Firebase controller
'''

import logging
import re

from pylons.i18n import _

import ckan.controllers.user as user
import ckan.lib.base as base
from ckan.common import g, request, response, config, session
import ckan.plugins.toolkit as toolkit
import json
import uuid
log = logging.getLogger(__name__)
from firebase_admin import auth


class UserFirebaseController(user.UserController):

    def login(self):
        """Login the user with credentials from the SocialAuth used. The CKAN
        username is created and access given.
        """

        login_path = base.config.get("ckanext.firebase.login_path", "/firebase/login")

        locale = request.environ.get('CKAN_LANG')
        login_path = re.sub('{{LANG}}', str(locale), login_path)

        # toolkit.request.environ
        # https://github.com/eHealthAfrica/ckanext-oauth2/blob/master/ckanext/oauth2/oauth2.py

        params = json.loads(request.body) #toolkit.request.params
       # decoded_token = auth.verify_id_token(id_token)
       # uid = decoded_token['uid']

        if 'uid' in params:
            user_account = params['email'].split('@')[0]
            full_name = params['displayName']
            user_email = params['email']
            if user_account.isalnum() is False:
                user_account = ''.join(e for e in user_account if e.isalnum())

            user_ckan = self.get_ckanuser(user_account)

            if not user_ckan:
                user_ckan = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
                    data_dict={'email': user_email,
                               'name': user_account,
                               'fullname': full_name,
                               'password': self.get_ckanpasswd()})

            session['ckanext_user'] = user_ckan['name']
            session['ckanext_email'] = user_email
            session.save()

        #return base.h.redirect_to(login_path)

        # if base.c.userobj is not None:
        #     log.info("Repoze.who Shibboleth controller received userobj %r " % base.c.userobj)
        #     return base.h.redirect_to(controller='user',
        #                               action='read',
        #                               id=base.c.userobj.name)
        # else:
        #     log.error("No userobj received in Repoze.who Shibboleth controller %r " % base.c)
        #     base.h.flash_error(_("No user info received for login"))
        #     return base.h.redirect_to('/')

    def get_ckanuser(self, user):
        """Return CKAN user if it already exists."""
        import ckan.model

        user_ckan = ckan.model.User.by_name(user)

        if user_ckan:
            user_dict = toolkit.get_action('user_show')(data_dict={'id': user_ckan.id})
            return user_dict
        else:
            return None

    def get_ckanpasswd(self):
        """Generate strong password for CKAN user."""
        import datetime
        import random
        passwd = str(random.random()) + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") + str(uuid.uuid4().hex)
        passwd = re.sub(r"\s+", "", passwd, flags=re.UNICODE)
        return passwd

    def _logout_user(self):
        """Log out the currently logged in CKAN user."""
        # import pylons
        # to revoke the Google token uncomment the code below
        # if 'ckanext_-accesstoken' in session:
        #    atoken = session.get('ckanext_-accesstoken')
        #    res = requests.get('https://accounts.google.com/o/oauth2/revoke?token='+atoken)
        #    if res.status_code == 200:
        #       del session['ckanext_-accesstoken']
        #    else:
        #   raise GoogleAuthException('Token not revoked')
        if 'ckanext_user' in session:
            del session['ckanext_user']
        if 'ckanext_email' in session:
            del session['ckanext_email']
        session.save()

    def logout(self):

        logout_path = base.config.get("ckanext.firebase.logout_path", "/firebase/logout")
        self._logout_user(self);
        #return base.h.redirect_to(logout_path)


