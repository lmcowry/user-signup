# Copyright 2016 Google Inc.
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

import webapp2
import cgi
import re


def valid_username(s):
    user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


# probably could just be if s:
    if user_re.match(s) == None:
        return None
    return user_re.match(s).group(0)

def escape_html(s):
    return cgi.escape(s, quote = True)

def valid_password(s):
    password_re = re.compile("^.{3,20}$")

    if password_re.match(s) == None:
        return None
    return password_re.match(s).group(0)

def valid_verify(s1, s2):
    if s1 != s2:
        return None
    else:
        return True

def valid_email(s):
    email_re = re.compile("^[\S]+@[\S]+.[\S]+$")

    if email_re.match(s) == None:
        return None
    return email_re.match(s).group(0)

thecontent = """
<h1>Signup</h1>
<form method="post">
    <table>
    <tr>
    <td><label for="username">Username</label></td>
    <td>
    <input type="text" name="username" value="%(username)s">
    <span style="color: red">%(error_username)s</span>
    </td>
    </tr>
    <tr>
    <td><label for="password">Password</label></td>
    <td>
    <input type="password" name="password" value="%(password)s">
    <span style="color: red">%(error_password)s</span>
    </td>
    </tr>
    <tr>
    <td><label for="verify">Verify Password</label></td>
    <td>
    <input type="password" name="verify" value="%(verify)s">
    <span style="color: red">%(error_verify)s</span>
    </td>
    </tr>
    <tr>
    <td><label for="email">Email (Optional)</label></td>
    <td>
    <input type="text" name="email" value="%(email)s">
    <span style="color: red">%(error_email)s</span>
    </td>
    </tr>
    </table>

    <input type="submit">


</form>"""





class SignUpHandler(webapp2.RequestHandler):
    def write_content(self, username="", error_username="", password="", error_password="", verify="", error_verify="", email="", error_email=""):
        self.response.out.write(thecontent % {"username": escape_html(username), "error_username": error_username, "password": escape_html(password), "error_password": error_password, "verify": verify, "error_verify": error_verify, "email": escape_html(email), "error_email": error_email})


    def get(self):
        self.write_content()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')

        user_email = ""
        escaped_email = ""
        validated_email = ""
        error_email = ""
        if self.request.get('email'):
            user_email = self.request.get('email')
            escaped_email = escape_html(user_email)
            validated_email = valid_email(escaped_email)
            if not (validated_email):
                error_email = "Your email is invalid"

        escaped_username = escape_html(user_username)
        escaped_password = escape_html(user_password)
        escaped_verify = escape_html(user_verify)

        validated_username = valid_username(escaped_username)
        validated_password = valid_password(escaped_password)
        validated_verify = valid_verify(escaped_verify, escaped_password)

        error_username = ""
        error_password = ""
        error_verify = ""




        if not (validated_username):
            error_username = "Your username is invalid"

        if not (validated_password):
            error_password = "Your password is invalid"

        if not (validated_verify):
            error_verify = "Your passwords don't match, dumbass"


        if (error_username or error_password or error_verify or error_email):
            self.write_content(escaped_username, error_username, "", error_password, "", error_verify, escaped_email, error_email)

        else:
            theURL = "/welcome"
            self.redirect("{0}?username={1}".format(theURL, validated_username))


class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        theUsername = self.request.get('username')

        self.response.out.write("Welcome, " + theUsername)


app = webapp2.WSGIApplication([
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
