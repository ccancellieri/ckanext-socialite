"""MIT License.

Copyright (c) 2020 Carlo Cancellieri @ FAO

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

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import json
from google.auth.transport import requests
#import requests

import logging


from ckan.common import g, request, response, config, session, c

#cloud_project_number: The project *number* for your Google Cloud project.
#          This is returned by 'gcloud projects describe $PROJECT_ID', or
#          in the Project Info card in Cloud Console.
def get_cloud_project_number():
    """Extract Client ID from config(.ini) file."""
    return config.get('ckan.cloud_project_number', '1036455980974')


# cloud_project_id: The project * ID * for your Google Cloud project.
def get_cloud_project_id():
    """Extract Hosted Domain from config(.ini) file."""
    return config.get('ckan.cloud_project_id', '125584094271098335')


class AuthException(Exception):
    """Exception to be raised for errors."""

    pass


class SocialitePlugin(plugins.SingletonPlugin):
    """Set up plugin for CKAN integration."""

    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config_):
        """Add resources used by the plugin into core config file."""
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'googleauth')

    def dummy(self):
        # https://github.com/ckan/ckanext-oauth2waad/blob/master/ckanext/oauth2waad/plugin.py
        return 0

    # if someone is logged in will be set the parameter c.user
    def identify(self):
        import identify

        jwtr = request.headers.environ.get('HTTP_X_GOOG_IAP_JWT_ASSERTION')
        # '**ERROR: JWT validation error Token has wrong audience /projects/1036455980974/global/backendServices/125584094271098335, expected /projects/1036455980974/global/backendServices/fao-maps-review**'
        try:
            user_id, user_email, error = identify.validate_iap_jwt_from_compute_engine(jwtr, get_cloud_project_number(), get_cloud_project_id())

            if user_id is not None and user_email is not None:

                nickname = user_email.split('@')[0]
                if nickname.isalnum() is False:
                    nickname = ''.join(e for e in nickname if e.isalnum())

                if nickname is None:
                    nickname = user_id

                logging.info("nickmane=" + nickname + " user_id=" + user_id + " user_email=" +
                             user_email + " errors: " + error)

                if nickname is not None:
                    if 'ckanext_user' not in session or \
                        'user' not in toolkit.c:

                    #if nickname and :

                        # fetch registered users (by name)
                        user_ckan = self.get_ckanuser(nickname)

                        if not user_ckan:
                            # no user found? let's create it

                            toolkit.c.user = nickname
                            # TODO c['userobj']

                            try:
                                user_ckan = toolkit.get_action('user_create')(
                                    context={'ignore_auth': True},
                                    data_dict={
                                            'id': user_id,
                                            'email': user_email,
                                            'name': nickname,
                                            'fullname': user_email.split('@')[0],
                                            'about': '',
                                            'password': self.get_ckanpasswd()}
                                )
                            except (ValueError,) as e:
                                logging.info("!!{}!!".format(e))
                                return None

                        # setup the current session with an existing ckan user
                        c['user'] = user_ckan['id']
                        # TODO c['userobj']
                        session['ckanext_user'] = user_ckan['name']
                        session['ckanext_email'] = user_ckan['email']
                        session.save()

                    if session['ckanext_user'] != nickname or c['user'] != nickname:
                        # I'm NOT expecting to be here
                        raise AuthException('Unable to identify user: ' + error)
                    else:
                        # fetch registered users (by name)
                        user_ckan = self.get_ckanuser(nickname)

                        # setup the current session with an existing ckan user
                        session['ckanext_user'] = user_ckan['name']
                        session['ckanext_email'] = user_ckan['email']
                        session.save()

                #return {user_email, nickname, user_id, error}
            else:
                logout_url = toolkit.url_for(controller='user',
                                             action='logout')


        except (ValueError) as e:
            logging.error("!!{}!!".format(e))

            # TODO redirect to IAP ???
            message = toolkit._(
                "Refreshing your GCIP session with"
                "access token has failed. Some functionality "
                "may not be available.")
            toolkit.helpers.flash(message, category='alert-error', allow_html=True,
                                  ignore_duplicate=True)
            return None



    def login(self):
        """Login the user with credentials from the SocialAuth used. The CKAN
        username is created and access given.
        """
        pass


    def logout(self):
        # invalidate tocken
        import identify
        #user_email, nickname, user_id = identify.

        # TODO invalidate token
        # TODO redirect to IAP ???
        #  logout_path = config.get("ckanext.firebase.logout_path", "/firebase/logout")
        #  self._logout_user(self);
        #  #return base.h.redirect_to(logout_path)

        pass

    def abort(self):
        """In case of any errors, calls _logout_user()."""
        pass

    def login(self):

        # TODO redirect
        pass

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
        import re
        import uuid
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

