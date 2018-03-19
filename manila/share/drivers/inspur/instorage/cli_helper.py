# Copyright 2018 Inspur Corp.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
CLI helpers for Inspur InStorage
"""

import paramiko
import re
import six

from eventlet import greenthread

from oslo_concurrency import processutils
from oslo_log import log
from oslo_utils import excutils

from manila import exception
from manila import utils as manila_utils
from manila.i18n import _

LOG = log.getLogger(__name__)


class SSHRunner(object):

    """ SSH runner to execute the command for inspur instorage """

    def __init__(self, host, port, login, password):
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.privatekey = None

        self.ssh_conn_timeout = 60
        self.ssh_min_pool_size = 1
        self.ssh_max_pool_size = 10

        self.sshpool = None

    def __call__(self, cmd_list, check_exit_code=True, attempts=1):
        """SSH tool"""
        manila_utils.check_ssh_injection(cmd_list)
        command = ' '.join(cmd_list)
        if not self.sshpool:
            try:
                self.sshpool = manila_utils.SSHPool(
                    self.host,
                    self.port,
                    self.ssh_conn_timeout,
                    self.login,
                    password=self.password,
                    privatekey=self.privatekey,
                    min_size=self.ssh_min_pool_size,
                    max_size=self.ssh_max_pool_size
                )
            except paramiko.SSHException:
                LOG.error("Unable to create SSHPool")
                raise
        try:
            return self._ssh_execute(self.sshpool, command,
                                     check_exit_code, attempts)
        except Exception:
            LOG.error("Error running SSH command: %s", command)
            raise

    def _ssh_execute(self, sshpool, command,
                     check_exit_code=True, attempts=1):
        try:
            with sshpool.item() as ssh:
                last_exception = None
                while attempts > 0:
                    attempts -= 1
                    try:
                        return processutils.ssh_execute(
                            ssh,
                            command,
                            check_exit_code=check_exit_code)
                    except Exception as e:
                        LOG.exception('Error has occurred')
                        last_exception = e
                        greenthread.sleep(1)

                try:
                    raise processutils.ProcessExecutionError(
                        exit_code=last_exception.exit_code,
                        stdout=last_exception.stdout,
                        stderr=last_exception.stderr,
                        cmd=last_exception.cmd)
                except AttributeError:
                    raise processutils.ProcessExecutionError(
                        exit_code=-1,
                        stdout="",
                        stderr="Error running SSH command",
                        cmd=command)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Error running SSH command: %s", command)


class CLIParser(object):
    """Parse MCS CLI output and generate iterable."""

    def __init__(self, raw, ssh_cmd=None, delim='!', with_header=True):
        super(CLIParser, self).__init__()
        if ssh_cmd:
            self.ssh_cmd = ' '.join(ssh_cmd)
        else:
            self.ssh_cmd = 'None'
        self.raw = raw
        self.delim = delim
        self.with_header = with_header
        self.result = self._parse()

    def select(self, *keys):
        for a in self.result:
            vs = []
            for k in keys:
                v = a.get(k, None)
                if isinstance(v, six.string_types) or v is None:
                    v = [v]
                if isinstance(v, list):
                    vs.append(v)
            for item in zip(*vs):
                if len(item) == 1:
                    yield item[0]
                else:
                    yield item

    def __getitem__(self, key):
        try:
            return self.result[key]
        except KeyError:
            msg = (_('Did not find the expected key %(key)s in %(fun)s: '
                     '%(raw)s.') % {'key': key, 'fun': self.ssh_cmd,
                                    'raw': self.raw})
            raise exception.ShareBackendException(msg=msg)

    def __iter__(self):
        for a in self.result:
            yield a

    def __len__(self):
        return len(self.result)

    def _parse(self):
        def get_reader(content, delim):
            for line in content.lstrip().splitlines():
                line = line.strip()
                if line:
                    yield line.split(delim)
                else:
                    yield []

        if isinstance(self.raw, six.string_types):
            stdout, stderr = self.raw, ''
        else:
            stdout, stderr = self.raw
        reader = get_reader(stdout, self.delim)
        result = []

        if self.with_header:
            hds = tuple()
            for row in reader:
                hds = row
                break
            for row in reader:
                cur = dict()
                if len(hds) != len(row):
                    msg = (_('Unexpected CLI response: header/row mismatch. '
                             'header: %(header)s, row: %(row)s.')
                           % {'header': hds,
                              'row': row})
                    raise exception.ShareBackendException(msg=msg)
                for k, v in zip(hds, row):
                    CLIParser.append_dict(cur, k, v)
                result.append(cur)
        else:
            cur = dict()
            for row in reader:
                if row:
                    CLIParser.append_dict(cur, row[0], ' '.join(row[1:]))
                elif cur:  # start new section
                    result.append(cur)
                    cur = dict()
            if cur:
                result.append(cur)
        return result

    @staticmethod
    def append_dict(dict_, key, value):
        key, value = key.strip(), value.strip()
        obj = dict_.get(key, None)
        if obj is None:
            dict_[key] = value
        elif isinstance(obj, list):
            obj.append(value)
            dict_[key] = obj
        else:
            dict_[key] = [obj, value]
        return dict_


class InStorageSSH(object):
    """SSH interface to Inspur InStorage systems."""

    def __init__(self, ssh_runner):
        self._ssh = ssh_runner

    def _run_ssh(self, ssh_cmd):
        try:
            return self._ssh(ssh_cmd)
        except processutils.ProcessExecutionError as e:
            msg = (_('CLI Exception output:\n command: %(cmd)s\n '
                     'stdout: %(out)s\n stderr: %(err)s.') %
                   {'cmd': ssh_cmd,
                    'out': e.stdout,
                    'err': e.stderr})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def run_ssh_inq(self, ssh_cmd, delim='!', with_header=False):
        """Run an SSH command and return parsed output."""
        raw = self._run_ssh(ssh_cmd)
        return CLIParser(raw, ssh_cmd=ssh_cmd, delim=delim,
                         with_header=with_header)

    def run_ssh_assert_no_output(self, ssh_cmd):
        """Run an SSH command and assert no output returned."""
        out, err = self._run_ssh(ssh_cmd)
        if len(out.strip()) != 0:
            msg = (_('Expected no output from CLI command %(cmd)s, '
                     'got %(out)s.') % {'cmd': ' '.join(ssh_cmd), 'out': out})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def run_ssh_check_created(self, ssh_cmd):
        """Run an SSH command and return the ID of the created object."""
        out, err = self._run_ssh(ssh_cmd)
        try:
            match_obj = re.search(r'\[([0-9]+)\],? successfully created', out)
            return match_obj.group(1)
        except (AttributeError, IndexError):
            msg = (_('Failed to parse CLI output:\n command: %(cmd)s\n '
                     'stdout: %(out)s\n stderr: %(err)s.') %
                   {'cmd': ssh_cmd,
                    'out': out,
                    'err': err})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def lsnode(self, node_id=None):
        with_header = True
        ssh_cmd = ['mcsinq', 'lsnode', '-delim', '!']
        if node_id:
            with_header = False
            ssh_cmd.append(node_id)
        return self.run_ssh_inq(ssh_cmd, with_header=with_header)

    def lsnaspool(self, pool_id=None):
        with_header = True
        ssh_cmd = ['mcsinq', 'lsnaspool', '-delim', '!']
        if pool_id:
            with_header = False
            ssh_cmd.append(pool_id)
        return self.run_ssh_inq(ssh_cmd, with_header=with_header)

    def lsfs(self, node_name=None, fsname=None):
        # TODO maybe need to check input value
        if fsname and not node_name:
            raise 0

        ssh_cmd = ['mcsinq', 'lsfs', '-delim', '!']
        to_append = []

        if node_name:
            to_append += ['-node', '"%s"' % node_name]

        if fsname:
            to_append += ['-name', '"%s"' % fsname]

        if not to_append:
            to_append += ['-all']

        ssh_cmd += to_append
        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def addfs(self, fsname, pool_name, size, node_name):
        """

        :param fsname: file system name
        :param pool_name: pool in which to create the file system
        :param size: file system size in GB and larger then 100
        :param node_name: the primary node name
        :return:
        """

        ssh_cmd = ['mcsop', 'addfs', '-name', '"%s"' % fsname, '-pool',
                   '"%s"' % pool_name, '-size', '%dg' % size,
                   '-node', '"%s"' % node_name]
        self.run_ssh_assert_no_output(ssh_cmd)

    def rmfs(self, fsname):
        """

        :param fsname: file system name to be removed
        :return:
        """

        ssh_cmd = ['mcsop', 'rmfs', '-name', '"%s"' % fsname]
        self.run_ssh_assert_no_output(ssh_cmd)

    def expandfs(self, fsname, size):
        """

        :param fsname:
        :param size: the size(GB) to be expanded, origin + size = result
        :return:
        """

        ssh_cmd = ['mcsop', 'expandfs', '-name', '"%s"' % fsname,
                   '-size', '%dg' % size]
        self.run_ssh_assert_no_output(ssh_cmd)

    # NAS directory operation
    def lsnasdir(self, dirpath):
        """
        list the child directory under dirpath

        :param dirpath: the parent directory to list with
        :return:
        """

        ssh_cmd = ['mcsinq', 'lsnasdir', '-delim', '!', '"%s"' % dirpath]
        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def addnasdir(self, dirpath):
        """
        create a new NAS directory indicate by dirpath

        :param dirpath: the NAS directory to be created
        :return:
        """

        ssh_cmd = ['mcsop', 'addnasdir', '"%s"' % dirpath]
        self.run_ssh_assert_no_output(ssh_cmd)

    def chnasdir(self, old_path, new_path):
        """

        :param old_path:
        :param new_path:
        :return:
        """

        ssh_cmd = ['mcsop', 'chnasdir', '-oldpath', '"%s"' % old_path,
                   '-newpath', '"%s"' % new_path]
        self.run_ssh_assert_no_output(ssh_cmd)

    def rmnasdir(self, dirpath):
        """

        :param dirpath:
        :return:
        """

        ssh_cmd = ['mcsop', 'rmnasdir', '"%s"' % dirpath]
        self.run_ssh_assert_no_output(ssh_cmd)

    ### NFS operation
    def rmnfs(self, share_path):
        """

        :param share_path:
        :return:
        """

        ssh_cmd = ['mcsop', 'rmnfs', '"%s"' % share_path]
        self.run_ssh_assert_no_output(ssh_cmd)

    def lsnfslist(self, prefix=None):
        """

        :param prefix:
        :return:
        """

        ssh_cmd = ['mcsinq', 'lsnfslist', '-delim', '!']
        if prefix:
            ssh_cmd.append('"%s"' % prefix)

        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def lsnfsinfo(self, share_path):
        """

        :param share_path:
        :return:
        """

        ssh_cmd = ['mcsinq', 'lsnfsinfo', '-delim', '!', '"%s"' % share_path]
        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def addnfsclient(self, share_path, client_spec):
        """

        :param share_path:
        :param client_spec: IP/MASK:RIGHTS:ALL_SQUASH:ROOT_SQUASH
        :return:
        """

        ssh_cmd = ['mcsop', 'addnfsclient', '-path', '"%s"' % share_path,
                   '-client', client_spec]
        self.run_ssh_assert_no_output(ssh_cmd)

    def chnfsclient(self, share_path, client_spec):
        """

        :param share_path:
        :param client_spec:
        :return:
        """

        ssh_cmd = ['mcsop', 'chnfsclient', '-path', '"%s"' % share_path,
                   '-client', client_spec]
        self.run_ssh_assert_no_output(ssh_cmd)

    def rmnfsclient(self, share_path, client_spec):
        """

        :param share_path:
        :param client_spec:
        :return:
        """
        # client_spec parameter for rm is IP/MASK, we need remove the follow
        # right part
        client_spec = client_spec.split(':')[0]

        ssh_cmd = ['mcsop', 'rmnfsclient', '-path', '"%s"' % share_path,
                   '-client', client_spec]
        self.run_ssh_assert_no_output(ssh_cmd)

    # CIFS operation
    def lscifslist(self, filter=None):
        """

        :param filter:
        :return:
        """
        ssh_cmd = ['mcsinq', 'lscifslist', '-delim', '!']
        if filter:
            ssh_cmd.append('"%s"' % filter)

        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def lscifsinfo(self, share_name):
        """

        :param share_name:
        :return:
        """
        ssh_cmd = ['mcsinq', 'lscifsinfo', '-delim', '!', '"%s"' % share_name]
        return self.run_ssh_inq(ssh_cmd, with_header=True)

    def addcifs(self, share_name, dirpath, oplocks='off'):
        """

        :param share_name:
        :param dirpath:
        :param oplocks:
        :return:
        """
        ssh_cmd = ['mcsop', 'addcifs', '-name', share_name, '-path', dirpath,
                   '-oplocks', oplocks]
        self.run_ssh_assert_no_output(ssh_cmd)

    def rmcifs(self, share_name):
        """

        :param share_name:
        :return:
        """
        ssh_cmd = ['mcsop', 'rmcifs', share_name]
        self.run_ssh_assert_no_output(ssh_cmd)

    def chcifs(self, share_name, oplocks='off'):
        """

        :param share_name:
        :param oplocks:
        :return:
        """
        ssh_cmd = ['mcsop', 'chcifs', '-name', share_name, '-oplocks', oplocks]
        self.run_ssh_assert_no_output(ssh_cmd)

    def addcifsuser(self, share_name, rights):
        """

        :param share_name:
        :param rights: [LU|LG]:xxx:[rw|ro]
        :return:
        """
        ssh_cmd = ['mcsop', 'addcifsuser', '-name', share_name,
                   '-rights', rights]
        self.run_ssh_assert_no_output(ssh_cmd)

    def chcifsuser(self, share_name, rights):
        """

        :param share_name:
        :param rights:
        :return:
        """
        ssh_cmd = ['mcsop', 'chcifsuser', '-name', share_name,
                   '-rights', rights]
        self.run_ssh_assert_no_output(ssh_cmd)

    def rmcifsuser(self, share_name, rights):
        """

        :param share_name:
        :param rights:
        :return:
        """
        # the rights parameter for rm is LU:NAME
        rights = ':'.join(rights.split(':')[0:-1])

        ssh_cmd = ['mcsop', 'rmcifsuser', '-name', share_name,
                   '-rights', rights]
        self.run_ssh_assert_no_output(ssh_cmd)

    # NAS port ip
    def lsnasportip(self):
        """

        :return:
        """

        ssh_cmd = ['mcsinq', 'lsnasportip', '-delim', '!']
        return self.run_ssh_inq(ssh_cmd, with_header=True)
