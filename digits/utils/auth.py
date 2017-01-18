# Copyright (c) 2015-2017, NVIDIA CORPORATION.  All rights reserved.
from __future__ import absolute_import

import flask
import functools
import re
import werkzeug.exceptions
import pickle
from werkzeug.security import generate_password_hash, \
    check_password_hash
import os
import tempfile
import digits
if 'DIGITS_MODE_TEST' in os.environ:
    value = tempfile.mkdtemp()
elif 'DIGITS_JOBS_DIR' in os.environ:
    value = os.environ['DIGITS_JOBS_DIR']
    value += "/../"
else:
    value = os.path.join(os.path.dirname(digits.__file__))+'/'
    print(value)

save_dir = value
try:
    users = pickle.load(open(save_dir + "users.p", "rb"))
except IOError:
    users = {}
from .routing import get_request_arg, request_wants_json


def get_username():
    return get_request_arg('username') or \
           flask.request.cookies.get('username', None)


def validate_username(username):
    """
    Raises a ValueError if the username is invalid
    """
    if not username:
        raise ValueError('username is required')
    if not re.match('[a-z]', username):
        raise ValueError('Must start with a lowercase letter')
    if not re.match('[a-z0-9\.\-_]+$', username):
        raise ValueError('Only lowercase letters, numbers, periods, dashes and underscores allowed')


def validate_password(password):
    """
    Raises a ValueError if the password is invalid
    """


def validate_user(username, password):
    if username not in users:
        users[username] = generate_password_hash(password)
        pickle.dump(users, open(save_dir + "users.p", "wb"))
    if not check_password_hash(users.get(username), password):
        raise ValueError("Bad password")


def requires_login(f=None, redirect=True):
    """
    Decorator for views that require the user to be logged in

    Keyword arguments:
    f -- the function to decorate
    redirect -- if True, this function may return a redirect
    """
    if f is None:
        # optional arguments are handled strangely
        return functools.partial(requires_login, redirect=redirect)

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        username = get_username()
        if not username:
            # Handle missing username
            if request_wants_json() or not redirect:
                raise werkzeug.exceptions.Unauthorized()
            else:
                return flask.redirect(flask.url_for('digits.views.login', next=flask.request.path))
        try:
            # Validate username
            validate_username(username)
        except ValueError as e:
            raise werkzeug.exceptions.BadRequest('Invalid username - %s' % e.message)
        return f(*args, **kwargs)

    return decorated


def has_permission(job, action, username=None):
    """
    Returns True if username can perform action on job

    Arguments:
    job -- the Job in question
    action -- the action in question

    Keyword arguments:
    username -- the user in question (defaults to current user)
    """
    if job.is_read_only():
        return False

    if username is None:
        username = get_username()

    if not username:
        return False
    if not job.username:
        return True
    return username == job.username
