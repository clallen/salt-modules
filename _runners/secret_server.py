# -*- coding: utf-8 -*-
'''
Runner for creating and managing secrets via the Secret Server REST API.

.. codeauthor:: Clint Allen <clint.allen.dev@gmail.com>
'''

from __future__ import absolute_import

# Python libs
import json
import logging
import requests

# Salt libs
from salt.exceptions import CommandExecutionError

PILLAR_DATA = {}


def __virtual__():
    ''' Get pillar data on module load '''
    master_id = __salt__['salt.cmd']('grains.get', 'id')
    all_data = __salt__['pillar.show_pillar'](minion=master_id)
    _ = all_data.get('master', {})
    ss_data = _.get('secret_server', '')
    if not ss_data:
        log = logging.getLogger(__name__)
        log.error('Secret Server pillar data not found, unable to load '
                  'runner module')
        return False

    PILLAR_DATA.update(ss_data)
    return True


class RestApi():
    '''
    Secret Server REST API singleton.
    Handles obtaining and caching a session authentication token, and
    encapsulates API calls.
    '''
    _instance = None

    def __init__(self):
        self._base_url = PILLAR_DATA.get('base_url', '')
        if not self._base_url:
            err_msg = 'Secret Server base API URL not found in pillar'
            raise LookupError(err_msg)
        self._req_headers = {'content-type': 'application/json'}
        self._log = logging.getLogger(__name__)

    def _refresh_token(self):
        '''

        Get a token from Secret Server, if the currently cached token is
        invalid or does not exist.

        Credentials are stored in the master's local minion grains:
        ```
        ni_unix:
          secret_server:
            username
            password
            domain
            grant_type
        ```
        The token is also cached in local minion grains:
        ```
        cache:
          secret_server:
            token
        ```

        Once the token is validated and cached, the `_req_headers` class
        attribute is set with it in the "authorization" field.
        '''
        resp = requests.get('{}/folders/lookup'.format(self._base_url),
                            params={'take': 1},
                            headers=self._req_headers)
        if resp.status_code == 403:
            auth_url = PILLAR_DATA.get('auth_url', '')
            if not auth_url:
                err_msg = 'Secret Server auth URL not found in pillar'
                raise LookupError(err_msg)
            ss_auth = __salt__['salt.cmd']('grains.get',
                                           'ni_unix:secret_server')
            if not ss_auth:
                err_msg = ('Secret Server credentials not found in master\'s '
                           'local minion grains')
                raise LookupError(err_msg)
            headers = {'accept': 'application/json',
                       'content-type': 'application/x-www-form-urlencoded'}
            resp = requests.post(auth_url, data=ss_auth, headers=headers)
            if resp.status_code not in (200, 304):
                err_msg = 'Error response for API call {}\nHTTP code: {}\n{}'
                raise CommandExecutionError(err_msg.format(auth_url,
                                                           resp.status_code,
                                                           resp.text))
            try:
                token = resp.json()['access_token']
            except Exception as err:
                err_msg = 'Bad response data from API call {}:\n{}'
                raise CommandExecutionError(err_msg.format(auth_url,
                                                           resp.text)) from err
            __salt__['salt.cmd']('grains.set', 'cache:secret_server:token',
                                 token)
            self._req_headers['authorization'] = 'Bearer {}'.format(token)

    @classmethod
    def get_instance(cls):
        ''' Get the singleton instance, instantiating a new one if needed '''
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _request(self, method, op_url, params=None, data=None):
        '''
        Wrapper for API calls.

        :param str method: One of GET, OPTIONS, HEAD, POST, PUT, PATCH,
        or DELETE
        :param str op_url: A Secret Server REST API URL
        :param dict params: Optional parameters passed via URL
        :param dict data: Optional data passed in request body
        :rtype: dict
        :returns: Data from the requests.Response.json() method
        :raises: CommandExecutionError on HTTP error response
        '''
        kwargs = {}
        if data is not None:
            kwargs['data'] = data
        if params is not None:
            kwargs['params'] = params
        req_url = '{}{}'.format(self._base_url, op_url)
        count = 1
        while count < 4:
            resp = requests.request(method, req_url, headers=self._req_headers,
                                    **kwargs)
            if resp.status_code == 403:
                self._refresh_token()
            elif resp.status_code not in (200, 304):
                err_tmpl = ('Error response for API call {} {}\nHTTP code: {}\n'
                            'Request params: {}\n'
                            'Message: {}')
                data = resp.json()
                err_msg = err_tmpl.format(method, req_url, resp.status_code,
                                          str(kwargs), data['message'])
                raise CommandExecutionError(err_msg)
            else:
                break
            count += 1
        self._log.debug('RestApi._request: API call %s %s', method, req_url)
        self._log.debug('RestApi._request: Request params: %s', kwargs)
        return resp.json()

    def get(self, op_url, params=None):
        '''
        Send a GET request to Secret Server.

        :param str op_url: A Secret Server REST API URL
        :param dict params: Optional parameters passed in URL
        :rtype: dict
        :returns: JSON data from the original requests.Response object
        '''
        response = self._request('GET', op_url, params=params)
        self._log.debug('RestApi.get: API response data: %s', response)
        return response

    def put(self, op_url, data=None):
        '''
        Send a PUT request to Secret Server.

        :param str op_url: A Secret Server REST API URL
        :param dict data: Optional data passed in request body
        :rtype: dict
        :returns: JSON data from the original requests.Response object
        '''
        response = self._request('PUT', op_url, data=data)
        self._log.debug('RestApi.get: API response data: %s', response)
        return response

    def post(self, op_url, data=None):
        '''
        Send a POST request to Secret Server.

        :param str op_url: A Secret Server REST API URL
        :param dict data: Optional data passed in request body
        :rtype: dict
        :returns: JSON data from the original requests.Response object
        '''
        response = self._request('POST', op_url, data=data)
        self._log.debug('RestApi.post: API response data: %s', response)
        return response

    def delete(self, op_url, params=None):
        '''
        Send a DELETE request to Secret Server.

        :param str op_url: A Secret Server REST API URL
        :param dict params: Optional parameters passed in URL
        :rtype: dict
        :returns: JSON data from the original requests.Response object
        '''
        response = self._request('DELETE', op_url, params=params)
        self._log.debug('RestApi.delete: API response data: %s', response)
        return response


class LookupSet(set):
    '''
    Encapsulates a set of secrets which match a given search text string and
    path, along with some convenience methods.

    :param str search: Text for which to search
    :param str path: Path in which to search - default is None, which searches
    from the root
    :param bool recurse: If True, search recursively into subfolders.  Default
    is False.
    '''
    def __init__(self, search, path=None, recurse=False):
        super().__init__()
        self.path = ''
        rest_api = RestApi.get_instance()
        params = {'filter.searchText': search,
                  'filter.includeSubFolders': recurse}
        if path is not None:
            self.path = path
            folder_id = LookupSet.get_folder_id(path)
            if not folder_id:
                err_msg = 'Folder ID not found for path "{}"'.format(path)
                raise LookupError(err_msg)
            params['filter.folderId'] = folder_id
        response = rest_api.get('/secrets/lookup', params=params)
        for record in response['records']:
            secret = Secret(record['id'])
            self.add(secret)

    @staticmethod
    def get_folder_id(path):
        '''
        Lookup a folder ID.

        :param str path: Path to folder (inclusive)
        :rtype: str
        '''
        ret = ''
        rest_api = RestApi.get_instance()
        folder_name = path.split('\\')[-1]
        params = {'filter.searchText': folder_name, 'take': 100}
        response = rest_api.get('/folders', params=params)
        for record in response['records']:
            if record['folderPath'] == path:
                ret = str(record['id'])
                break
        return ret

    def get_exact(self, name, path=None):
        '''
        Convenience method for finding a specific secret.

        :param str name: Secret name
        :param str path: Secret path. If None, the path used to create this
        LookupSet instance.  Default is None.
        :rtype: Secret
        :returns: The Secret that matches, otherwise None
        '''
        ret = None
        if path is None:
            path = self.path
        for secret in self:
            if all([secret.name == name,
                    secret.path == path]):
                ret = secret
                break
        return ret


class Secret():
    '''
    Single secret data and methods.
    '''
    def __init__(self, ID):
        self._log = logging.getLogger(__name__)
        self.ID = ID
        self.name = ''
        self.folder_id = ''
        self.path = ''
        self.pw_field_id = ''
        self.username = ''
        self.password = ''
        self.machine = ''
        self.notes = ''
        # Get secret data
        rest_api = RestApi.get_instance()
        response = rest_api.get('/secrets/{}'.format(self.ID))
        self.name = response['name']
        self.folder_id = response['folderId']
        for item in response['items']:
            if item['slug'] == 'username':
                self.username = item['itemValue']
            elif item['slug'] == 'password':
                self.password = item['itemValue']
                self.pw_field_id = item['fieldId']
            elif item['slug'] == 'machine':
                self.machine = item['itemValue']
            elif item['slug'] == 'notes':
                self.notes = item['itemValue']
        # Get folder path
        # BUG: Not using direct ID lookup (GET /folders/{id}) here because for
        # some reason SS always returns API_AccessDenied
        response = rest_api.get('/folders', params={'take': 100})
        for record in response['records']:
            if record['id'] == self.folder_id:
                self.path = record['folderPath']
                break
        if not self.path:
            err_msg = 'Path for secret {} not found, using folder ID {}'
            raise LookupError(err_msg.format(self.name, self.folder_id))

    def generate_password(self):
        '''
        Generate a new password via the API call
        "POST /secret-templates/generate-password".  The ID of this secret's
        "Password" field is used as the "secretFieldId" argument to the call.

        :rtype: str
        '''
        rest_api = RestApi.get_instance()
        op_url = '/secret-templates/generate-password'
        password = rest_api.post('{}/{}'.format(op_url, self.pw_field_id))
        self._log.debug('Password generated: "%s"', password)
        return password

    def change_password(self, password):
        '''
        Change this secret's password on Secret Server.
        This utilizes the PUT /secrets/{id}/restricted/fields/{slug} method,
        and does not trigger remote password changing.

        :param str password: Password to set
        '''
        rest_api = RestApi.get_instance()
        args = {'value': password,
                'comment': 'Changed via Salt runner (Secret.change_password)'}
        op_url = '/secrets/{}/restricted/fields/password'
        rest_api.put(op_url.format(self.ID), data=json.dumps(args))
        self._log.info('Password changed in secret "%s"', self.name)

    def change_password_remote(self, password):
        '''
        Change this secret's password on Secret Server.
        This utilizes the POST /secrets/{id}/change-password method,
        and triggers remote password changing.

        :param str password: Password to set
        '''
        rest_api = RestApi.get_instance()
        args = {'newPassword': password,
                'comment': ('Changed via Salt runner '
                            '(Secret.change_password_remote)')}
        op_url = '/secrets/{}/change-password'
        rest_api.post(op_url.format(self.ID), data=json.dumps(args))
        self._log.info('Password changed in secret "%s"', self.name)

    def delete(self):
        '''
        Delete this secret from Secret Server.
        '''
        rest_api = RestApi.get_instance()
        rest_api.delete('/secrets/{}'.format(self.ID))
        self._log.info('Secret "%s" deleted', self.ID)


class NewSecret(Secret):
    '''
    A secret that will be created.  If an existing secret with the same name and
    path is found, it is deleted and recreated.
    '''
    def __init__(self, name, template, path, item_data):
        '''
        :param str name: Secret name
        :param str template: Template to use in secret creation
        :param str path: Full path to folder in which to create secret
        :param dict item_data: Template-dependent secret item data (see the
        "items" field in SecretCreateArgs).
        Keys must match "slug" fields defined in RestSecretItem, values will be
        set in the item's "itemValue" field.
        '''
        self._log = logging.getLogger(__name__)
        rest_api = RestApi.get_instance()
        # Delete existing secret, if any
        lookup = LookupSet(name, path)
        old_secret = lookup.get_exact(name)
        if old_secret is not None:
            old_secret.delete()
        # Lookup template ID
        params = {'filter.searchText': template, 'take': 1000}
        response = rest_api.get('/secret-templates', params=params)
        template_id = ''
        for record in response['records']:
            if record['name'] == template:
                template_id = str(record['id'])
                log_msg = 'ID found for template "%s": %s'
                self._log.info(log_msg, template, template_id)
        if not template_id:
            err_msg = 'ID not found for template "{}"'.format(template)
            raise LookupError(err_msg)
        # Lookup folder ID
        folder_id = LookupSet.get_folder_id(path)
        if not folder_id:
            raise LookupError('Folder ID not found for path "{}"'.format(path))
        # Get secret stub
        params = {'secretTemplateId': template_id,
                  'folderId': folder_id}
        stub = rest_api.get('/secrets/stub', params)
        log_str = 'Got stub for template "%s", path "%s"'
        self._log.info(log_str, template, path)
        # Get site ID
        site_id = PILLAR_DATA.get('site_id', 0)
        if site_id == 0:
            raise LookupError('Secret Server site ID not found in pillar')
        # Populate stub
        stub['siteId'] = site_id
        stub['name'] = name
        for item in stub['items']:
            input_val = item_data.get(item['slug'], '')
            if input_val:
                item['itemValue'] = input_val
        # Create secret
        response = rest_api.post('/secrets', data=json.dumps(stub))
        ID = str(response['id'])
        super().__init__(ID)
        log_msg = 'Secret "%s" created using template "%s", in path "%s": ID %s'
        self._log.info(log_msg, name, template, path, self.ID)


def initialize_root_secret(hostname):
    '''
    Create a new root password secret in Secret Server.  This is intended for
    use with new system builds.

    The secret name format will be "unix_[hostname]_root".

    Folder path and template name are defined in pillar:
    ```
    master:
      secret_server:
        root_pw_path
        root_pw_template
    ```
    The initial password is stored in Secret Server.  Its folder path and
    secret name are defined in pillar:
    ```
    master:
      secret_server:
        unix_pw_path
        initial_root_secret
    ```
    Note: this data is restricted to the masters themselves, and can be
    accessed on the command line with:
    ```
    salt-run pillar.show_pillar minion=saline1_master
    ```

    After creating the secret with the `initial_root_secret` password, Secret
    Server will be used to generate a new password and change it.

    :param str hostname: Server for which to create secret
    :rtype: bool
    :returns: True on success, False on failure; errors are logged
    '''
    log = logging.getLogger(__name__)
    try:
        # Get pillar data
        path = PILLAR_DATA['root_pw_path']
        unix_pw_path = PILLAR_DATA['unix_pw_path']
        template = PILLAR_DATA['root_pw_template']
        initial_root_secret = PILLAR_DATA['initial_root_secret']
    except KeyError as err:
        key = str(err).strip('\'')
        log.error('Pillar key not found: "secret_server:%s"', key)
        return False
    try:
        # Get initial root password
        lookup = LookupSet(initial_root_secret, path=unix_pw_path)
        init_secret = lookup.get_exact(initial_root_secret)
        if init_secret is None:
            err_msg = 'Inital root secret "{}" not found'
            raise LookupError(err_msg.format(initial_root_secret))
        init_pw = init_secret.password
        # Create new secret
        name = 'unix_{}_root'.format(hostname)
        item_data = {'machine': hostname,
                     'username': 'root',
                     'password': init_pw}
        secret = NewSecret(name, template, path, item_data)
        # Generate and set new password
        new_pw = secret.generate_password()
        secret.change_password_remote(new_pw)
    except (LookupError, CommandExecutionError, KeyError) as err:
        log.error(str(err))
        return False
    return True


def get_passwords(search_text):
    '''
    Retrieve passwords from secrets with names that match the given text.

    :param str search_text: Text to search for in secret names
    :rtype: str
    :returns: Formatted secret data from matching secrets
    Example:
    ```
    -----------------------------------
    Secret name: [name]
    Username: [username]
    Password: [password]
    -----------------------------------
    Secret name: [name]
    Username: [username]
    Password: [password]
    -----------------------------------
    ...
    ```
    '''
    try:
        lookup = LookupSet(search_text, recurse=True)
    except (LookupError, CommandExecutionError, KeyError) as err:
        return str(err)
    lines = []
    for secret in lookup:
        lines.append('-----------------------------------')
        lines.append('Secret name: {}'.format(secret.name))
        lines.append('Username: {}'.format(secret.username))
        lines.append('Password: {}'.format(secret.password))
    if lines:
        lines.append('-----------------------------------')
        ret = '\n'.join(lines)
    else:
        ret = 'No matches found'
    return ret


def get_single_password(secret_name, path):
    '''
    Retrieve a password from the secret which exactly matches the given
    parameters.

    :param str secret_name: Name of secret to match
    :param str path: Path to secret
    :rtype: str
    :returns: Password, or empty string if not found
    '''
    ret = ''
    try:
        lookup = LookupSet(secret_name, path=path)
        secret = lookup.get_exact(secret_name)
        if secret is not None:
            ret = secret.password
    except (LookupError, CommandExecutionError, KeyError) as err:
        log = logging.getLogger(__name__)
        log.error(str(err))
    return ret


def generate_secret(secret_name, path, template, item_data, new_pw=True):
    '''
    Create a new secret, or replace an existing one.
    A password can be passed in item_data, or optionally a new password can be
    generated.
    If a new password is generated, the backend API call used by this function
    will not trigger remote password changing by Secret Server.

    :param str secret_name: Name of secret to create/replace
    :param str path: Path to secret to create/replace
    :param str template: Template to use in secret creation
    :param dict item_data: Template-dependent secret item data (see the "items"
    field in SecretCreateArgs).
    Keys must match "slug" fields defined in RestSecretItem, values will be set
    in the item's "itemValue" field.
    :param bool new_pw: If True, generate and set a new password in the secret.
    Default is True.
    :rtype: bool
    :returns: True on success, False on failure; errors are logged
    '''
    ret = True
    try:
        # Use a placeholder password if one is not passed in; this
        # prevents the "Secret field is required" error
        if 'password' not in item_data:
            item_data['password'] = 'password'
        secret = NewSecret(secret_name, template, path, item_data)
        if new_pw:
            password = secret.generate_password()
            secret.change_password(password)
    except (LookupError, CommandExecutionError, KeyError) as err:
        log = logging.getLogger(__name__)
        log.error(str(err))
        ret = False
    return ret


def change_password(secret_name, path, password=None):
    '''
    Update the password field of an existing Secret.

    :param str secret_name: Name of secret to update
    :param str path: Path to secret to update
    :param dict password: Password to set - if None, a new one will be generated
    by Secret Server using the Secret's template rules.  Default is None.
    :rtype: bool
    :returns: True on success, False on failure; errors are logged
    '''
    ret = True
    log = logging.getLogger(__name__)
    try:
        lookupset = LookupSet(secret_name, path)
        secret = lookupset.get_exact(secret_name)
        if secret is None:
            msg = 'Secret (%s) not found in path (%s)'
            log.error(msg, secret_name, path)
            ret = False
        else:
            if password is None:
                newpw = secret.generate_password()
            else:
                newpw = password
            secret.change_password(newpw)
    except (LookupError, CommandExecutionError, KeyError) as err:
        log.error(str(err))
        ret = False
    return ret


def generate_password(secret_name, path):
    '''
    Generate a password using the given Secret's template rules.

    :param str secret_name: Name of secret to lookup
    :param str path: Path to secret
    :rtype: str
    :returns: New password
    '''
    log = logging.getLogger(__name__)
    try:
        lookupset = LookupSet(secret_name, path)
        secret = lookupset.get_exact(secret_name)
        if secret is None:
            msg = 'Secret (%s) not found in path (%s)'
            log.error(msg, secret_name, path)
            ret = msg
        else:
            ret = secret.generate_password()
    except (LookupError, CommandExecutionError, KeyError) as err:
        log.error(str(err))
        ret = str(err)
    return ret
