#!/usr/bin/env python
import requests
import json

## Debug HTTP requests.
#import http.client
#http.client.HTTPConnection.debuglevel = 1
#import logging
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True
##


class ChaosAPI:
    """Andrews & Arnold CHAOS API as per http://aa.net.uk/support-chaos.html"""

    API_URL = 'https://chaos.aa.net.uk'

    def __init__(self, username=None, account=None, password=None):
        """Initialize a new ChaosAPI session with the either username+password or account+password for authentication."""

        if not (username or account):
            raise ValueError('Must specify username or account.')
        if username and account:
            raise ValueError('Specify either username or account, not both.')
        if password is None:
            raise ValueError('Missing password argument.')
        self.username, self.account, self.password = username, account, password
        self.session = None

    def _post(self, endpoint, data={}, *args, **kwargs):
        """Performs requests with authentication and session management."""

        if not self.session:  # Authenticate.
            auth = {'password': self.password}
            if self.account:
                auth['account'] = self.account
            else:
                auth['username'] = self.username
        else:  # Use existing session.
            auth = dict(session=self.session)
        data.update(auth)

        resp = requests.post(
            "{}/{}".format(self.API_URL, endpoint),
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data)
        )
        if resp.status_code == 200 and resp.headers.get('Content-Type', None) == 'application/json':
            data = resp.json()
        else:
            raise ValueError('Response not in JSON format.')

        if not 'session' in data:
            raise KeyError('No session attribute in response.')
        # TODO: Uncomment when CHAOS sessions are working
        #self.session = data['session']

        return data

    def new(self):
        """Start new session and return API information."""
        return self._post('new')

    def info(self, broadband_ids=[], login_ids=[]):
        """Retrieve info about objects under this account. Optionally filter to include only specifid broadband_ids and login_ids."""
        data = {}
        if broadband_ids:
            data.update({'broadband': [ {'ID': id_} for id_ in broadband_ids ]})
        if login_ids:
            data.update({'login': [ {'ID': id_} for id_ in login_ids ]})
        return self._post('info', data=data)


if __name__ == "__main__":
    import sys, re
    from pprint import pprint

    if len(sys.argv) != 3:
        print("Usage: {} user_or_accountname password".format(sys.argv[0]))
        sys.exit(1)
    login, password = sys.argv[1:]

    # Auto-detect login type.
    if re.match('^A\d+A$', login):  # Account (priceless)
        capi = ChaosAPI(account=login, password=password)
    else:  # Username (clueless)
        capi = ChaosAPI(username=login, password=password)

    # Examples
    print("### new")
    pprint(capi.new())
    print("### info")
    pprint(capi.info())
    print("### info with filter")
    pprint(capi.info(broadband_ids=[1234], login_ids=['xx99@a']))
