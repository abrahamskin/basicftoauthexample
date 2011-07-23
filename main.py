#!/usr/bin/env python
#
# Copyright 2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import urllib, simplejson

from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

# The following information is obtained when you register your
# application here: https://code.google.com/apis/console
# Save this information somewhere secure
client_id = "xyz.apps.googleusercontent.com"
client_secret = "abc"
redirect_uri = "http://basicftoauthexample.appspot.com/oauth2callback"


def main():
  """ Define URLS """
  application = webapp.WSGIApplication(
    [
      ('/', MainHandler), # index page
      ('/oauth2callback', OAuthCallback), # handle callback from Google
      ('/show', ShowTables) # show user's tables
    ],
    debug=True)
  util.run_wsgi_app(application)


class UserTokens(db.Model):
  """ Database for saving user tokens """
  user = db.UserProperty()
  access_token = db.StringProperty(required=True)
  refresh_token = db.StringProperty(required=True)


class MainHandler(webapp.RequestHandler):
  """ Handles requests for the index page """
  def get(self):
    user = users.get_current_user()

    # If the user has not logged in, redirect to login page
    if not user:
      self.redirect(users.create_login_url("/"))

    # Otherwise ...
    else:
      # Find any matching users in the database
      user_id = user.user_id()
      user_key = db.Key.from_path('UserTokens', user_id)
      user_token = db.get(user_key)

      # If the user exists in database, redirect to /show
      if user_token:
        self.redirect('/show')

      # Otherwise, start the process of OAuth
      else:
        self.redirect(
          '%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code' % \
            ('https://accounts.google.com/o/oauth2/auth',
            client_id,
            redirect_uri,
            'https://www.google.com/fusiontables/api/query')
        )


class OAuthCallback(webapp.RequestHandler):
  """ Handles callback from Google's Authorization page """
  def get(self):
    # Get the authorization code that's a parameter of the URL
    authorization_code = self.request.get('code')

    # Request access and refresh tokens from Google
    data = urllib.urlencode({
      'code': authorization_code,
      'client_id': client_id,
      'client_secret': client_secret,
      'redirect_uri': redirect_uri,
      'grant_type': 'authorization_code'
    })
    response = urlfetch.fetch(
      url='https://accounts.google.com/o/oauth2/token',
      payload = data,
      method = urlfetch.POST,
      headers = {'Content-Type': 'application/x-www-form-urlencoded'},
      deadline = 10).content
    tokens = simplejson.loads(response)
    access_token = tokens['access_token']
    refresh_token = tokens['refresh_token']
    user = users.get_current_user()

    # Save the tokens in the database
    userTokens = UserTokens(
      user = user,
      access_token = access_token,
      refresh_token = refresh_token)
    userTokens.put()

    # Redirect to /show page
    self.redirect('/show')


class ShowTables(webapp.RequestHandler):
  """ Shows the user's Fusion Tables """
  def get(self):
    # Find the current user in the database
    user = users.get_current_user()
    user_id = user.user_id()
    user_key = db.Key.from_path('UserTokens', user_id)
    user_token = db.get(user_key)

    # Send a query to Fusion Tables
    response = self.send_query(user_token.access_token)

    # If a 401 is returned and not because the user doesn't have
    # permissions, then access token is refreshed
    if response.status_code == 401 and \
        not response.content.find("User does not have permission") != -1:
 
      # Refresh access token
      access_token = self.refresh_token(user_token)

      # Send request again
      response = self.send_query(access_token)

    # Write the response
    self.response.out.write(response.content)

  def send_query(self, access_token):
    """ Sends query to Fusion Tables to SHOW TABLES,
        OAuth access token sent as parameter """
    return urlfetch.fetch(
      url = 'https://www.google.com/fusiontables/api/query?%s' % \
        urllib.urlencode({
          'sql': 'SHOW TABLES',
          'oauth_token': access_token
        }),
      deadline = 10
    )

  def refresh_token(self, user_token):
    """ Refresh access token using refresh token """
    data = urllib.urlencode({
      'client_id': client_id,
      'client_secret': client_secret,
      'refresh_token': user_token.refresh_token,
      'grant_type': 'refresh_token'
    })
    response = urlfetch.fetch(
      url='https://accounts.google.com/o/oauth2/token',
      payload = data,
      method = urlfetch.POST,
      headers = {'Content-Type': 'application/x-www-form-urlencoded'},
      deadline = 10).content
    tokens = simplejson.loads(response)
    access_token = tokens['access_token']

    # Replace the old access token in the database
    user_token.access_token = access_token
    user_token.save()

    return access_token

if __name__ == '__main__':
  main()
