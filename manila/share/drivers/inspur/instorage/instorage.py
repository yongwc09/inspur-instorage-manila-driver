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
Driver for Inspur InStorage
"""

import ipaddress
import itertools
import six

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share import utils as share_utils

from manila.share.drivers.inspur.instorage.cli_helper import InStorageSSH
from manila.share.drivers.inspur.instorage.cli_helper import SSHRunner

LOG = log.getLogger(__name__)

instorage_opts = [
    cfg.HostAddressOpt(
        'instorage_nas_ip',
        required=True,
        help='IP address for the InStorage.'
    ),
    cfg.ProtOpt(
        'instorage_nas_port',
        default=22,
        help='Port number for the InStorage.'
    ),
    cfg.StrOpt(
        'instorage_nas_login',
        required=True,
        help='Username for the InStorage.'
    ),
    cfg.StrOpt(
        'instorage_nas_password',
        required=True,
        secret=True,
        help='Password for the InStorage.'
    )
]

CONF = cfg.CONF
CONF.register_opts(instorage_opts)

LOG = logging.getLogger(__name__)


class InStorageShareDriver(driver.ShareDriver):
    """Inspur InStorage NAS driver. Allows for NFS and CIFS NAS.

    .. code::none
        Version history:
            1.0.0 - Initial driver.
                    Driver support:
                        share create/delete
                        extend size
                        update_access
                        protocol: NFS/CIFS
    """

    VENDOR = 'INSPUR'
    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(InStorageShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(instorage_opts)

        self.backend_name = self.configuration.safe_get('share_backend_name')

        self.ssh_runner = SSHRunner(**dict(
            host=self.configuration.instorage_nas_ip,
            port=22,
            login=self.configuration.instorage_nas_login,
            password=self.configuration.instorage_nas_password))

        self.assistant = InStorageAssistant(self.ssh_runner)

    def _update_share_stats(self, **kwargs):
        """
        retrieve share stats information.

        :param kwargs:
        :return:
        """

        try:
            stats = dict()
            stats['share_backend_name'] = self.backend_name
            stats['vendor_name'] = self.VENDOR
            stats['driver_version'] = self.VERSION
            stats['storage_protocol'] = 'NFS_CIFS'
            stats['snapshot_support'] = False
            stats['create_share_from_snapshot_support'] = False
            stats['revert_to_snapshot_support'] = False
            stats['qos'] = False
            stats['total_capacity_gb'] = 0.0
            stats['free_capacity_gb'] = 0.0
            stats['pools'] = []

            pools = self.assistant.get_pools_attr()
            total_capacity_gb = 0
            free_capacity_gb = 0
            for pool in pools.values():
                total_capacity_gb += pool['total_capacity_gb']
                free_capacity_gb += pool['free_capacity_gb']
                stats['pools'].append(pool)

            stats['total_capacity_gb'] = total_capacity_gb
            stats['free_capacity_gb'] = free_capacity_gb

            LOG.debug('share status %s', stats)

            super(InStorageShareDriver, self)._update_share_stats(stats)
        except Exception:
            msg = _('Unexpected error while trying to get the '
                    'usage stats from array.')
            LOG.exception(msg)
            raise

    @staticmethod
    def generate_share_name(share):
        # as the name length of the underlay limit to 32 chars,
        # we use the id and erase the '-' as the name
        # and we change all alpha to lower case
        # also the name in the system should not start with num,
        # we need change the head char if it is a num,
        # we change it to upper alpha start from 'A', as '0' -> 'A'

        name = share['id'].replace('-', '').lower()
        if name[0] in '0123456789':
            name = chr(ord('A') + (ord(name[0]) - ord('0'))) + name[1:]
        return name

    def check_for_setup_error(self):
        nodes = self.assistant.get_nodes_info()
        if len(nodes) == 0:
            msg = _('No valid node, be sure the NAS Port IP is configured')
            raise exception.ShareBackendException(msg=msg)

    def get_network_allocations_number(self):
        """
        Get the number of network interfaces to be created.
        :return:
        """

        return 0

    def create_share(self, context, share, share_server=None):
        """
        for share create process

        :param context:
        :param share:
        :param share_server:
        :return:
        """
        share_name = self.generate_share_name(share)
        share_size = share['size']
        share_proto = share['share_proto']

        pool_name = share_utils.extract_host(share['host'], level='pool')

        self.assistant.create_share(share_name, pool_name, share_size, share_proto)

        return self.assistant.get_export_locations(share_name, share_proto)

    def extend_share(self, share, new_size, share_server=None):
        """
        extend the share space

        :param share:
        :param new_size:
        :param share_server:
        :return:
        """
        share_name = self.generate_share_name(share)

        self.assistant.extend_share(share_name, new_size)

    def shrink_share(self, shrink_share, shrink_size, share_server=None):
        """
        shrink the share space

        :param shrink_share:
        :param shrink_size:
        :param share_server:
        :return:
        """
        raise NotImplementedError()

    def delete_share(self, context, share, share_server=None):
        """
        delete the share

        :param context:
        :param share:
        :param share_server:
        :return:
        """
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        self.assistant.delete_share(share_name, share_proto)

    def create_snapshot(self, context, snapshot, share_server=None):
        """
        create share's snapshot, now not support for it

        :param context:
        :param snapshot:
        :param share_server:
        :return:
        """
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """
        create a share base on the snapshot

        :param context:
        :param share:
        :param snapshot:
        :param share_server:
        :return:
        """
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot, share_server=None):
        """
        delete the share snapshot
        :param context:
        :param snapshot:
        :param share_server:
        :return:
        """
        raise NotImplementedError()

    def ensure_share(self, context, share, share_server=None):
        """

        :param context:
        :param share:
        :param share_server:
        :return:
        """
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        return self.assistant.get_export_locations(share_name, share_proto)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """

        :param context:
        :param share:
        :param access_rules:
        :param add_rules:
        :param delete_rules:
        :param share_server:
        :return:
        """
        share_name = self.generate_share_name(share)
        share_proto = share['share_proto']

        self.assistant.update_access(share_name, share_proto,
                                     access_rules, add_rules, delete_rules)


class InStorageAssistant(object):

    def __init__(self, ssh_runner):
        self.ssh = InStorageSSH(ssh_runner)

    @staticmethod
    def handle_keyerror(cmd, out):
        msg = (_('Could not find key in output of command %(cmd)s: %(out)s.')
               % {'out': out, 'cmd': cmd})
        raise exception.ShareBackendException(msg=msg)

    def change_size_to_gb(self, size):
        new_size = 0

        if 'T' in size:
            new_size = int(float(size.rstrip('TB')) * 1024)
        elif 'G' in size:
            new_size = int(float(size.rstrip('GB')) * 1)

        return new_size

    def get_pools_attr(self):
        pools = {}
        fs_attr = self.ssh.lsfs()
        pool_attr = self.ssh.lsnaspool()
        for attr in pool_attr:
            pool_name = attr['pool_name']
            total_used_capacity = 0
            total_total_capacity = 0
            for fs in fs_attr:
                if fs['pool_name'] != pool_name:
                    continue
                total = self.change_size_to_gb(fs['total_capacity'])
                used = self.change_size_to_gb(fs['used_capacity'])

                total_total_capacity += total
                total_used_capacity += used
            
            available = self.change_size_to_gb(attr['available_capacity'])

            pool = dict(
                pool_name=pool_name,
                total_capacity_gb=(total_total_capacity + available),
                free_capacity_gb=available,
                allocated_capacity_gb=total_total_capacity,

                qos=False,
                reserved_percentage=0,
                dedupe=False,
                compression=False,
                thin_provisioning=False,
                max_over_subscription_ratio=0
            )

            pools[pool_name] = pool

        return pools

    def get_nodes_info(self):
        """Return a dictionary containing information of system's nodes."""
        nodes = {}
        resp = self.ssh.lsnasportip()
        for port in resp:
            try:
                # port node configured IP is invalid
                if port['ip'] == '':
                    continue

                node_name = port['node_name']
                if node_name not in nodes:
                    nodes[node_name] = {}

                node = nodes[node_name]
                node[port['id']] = port 
            except KeyError:
                self.handle_keyerror('lsnasportip', port)

        return nodes

    @staticmethod
    def get_fsname_by_name(name):
        return ('%(fsname)s' % dict(fsname=name))[0:32]
    
    @staticmethod
    def get_dirname_by_name(name):
        return ('%(dirname)s' % dict(dirname=name))[0:32]

    def get_dirpath_by_name(self, share_name):
        fsname = self.get_fsname_by_name(share_name)
        dirname = self.get_dirname_by_name(share_name)

        return '/fs/%(fsname)s/%(dirname)s' % dict(fsname=fsname,
                                                   dirname=dirname)

    def create_share(self, name, pool, size, proto):
        """

        :param name:
        :param pool:
        :param size:
        :return:
        """

        # use one available node as the primary node
        nodes = self.get_nodes_info()
        if len(nodes) == 0:
            msg = _('No valid node, be sure the NAS Port IP is configured')
            raise exception.ShareBackendException(msg=msg)

        node_name = [key for key in nodes.keys()][0]

        # first create the file system on which share will be created
        fsname = self.get_fsname_by_name(name)
        self.ssh.addfs(fsname, pool, size, node_name)

        # then create the directory used for the share
        dirpath = self.get_dirpath_by_name(name)
        self.ssh.addnasdir(dirpath)

        # when for CIFS, we need create a CIFS share base on the directory
        # NFS is enabled when client spec is added, no need to add separate
        if proto == 'CIFS':
            self.ssh.addcifs(name, dirpath)

    def delete_share(self, name, proto):
        """

        :param name:
        :return:
        """

        dirpath = self.get_dirpath_by_name(name)

        # first delete all the NAS service like NFS and CIFS
        # NFS no need to delete, as no client spec no NFS, client
        # spec will delete before share delete
        if proto == 'CIFS':
            self.ssh.rmcifs(name)

        # then delete the directory
        self.ssh.rmnasdir(dirpath)

        # at last delete the file system
        fsname=self.get_fsname_by_name(name)
        self.ssh.rmfs(fsname)

    def extend_share(self, name, new_size):
        """Extend a given share to a new size.

        :param name: the name of the share.
        :param new_size: the new size the share should be.
        :return:
        """
        # first get the original capacity
        old_size = None
        fsname = self.get_fsname_by_name(name)
        for fs in self.ssh.lsfs():
            if fs['fs_name'] == fsname:
                old_size = self.change_size_to_gb(fs['total_capacity'])
                break

        if old_size is None:
            msg = _('share %s is not available') % name
            raise exception.ShareBackendException(msg=msg)

        LOG.debug('Extend fs %s from %dGB to %dGB', fsname, old_size, new_size)
        self.ssh.expandfs(fsname, new_size - old_size)

    def get_export_locations(self, name, share_proto):
        """Get the export locations of a given share.

        :param name: the name of the share.
        :param share_proto: the protocol of the share.
        :return: a list of export location.
        """

        if share_proto == 'NFS':
            dirpath = self.get_dirpath_by_name(name)
            partern = '%(ip)s:' + dirpath
        elif share_proto == 'CIFS':
            partern = '\\\\%(ip)s\\' + name
        else:
            msg = _('share protocol is not support') % share_proto
            raise exception.ShareBackendException(msg=msg)

        # we need get the node so that we know which port ip we can use
        node_name = None
        fsname = self.get_fsname_by_name(name)
        for node in self.ssh.lsnode():
            for fs in self.ssh.lsfs(node['name']):
                if fs['fs_name'] == fsname:
                    node_name = node['name']
                    break
            if node_name:
                break

        if node_name is None:
            msg = _('share %s is not available') % name
            raise exception.ShareBackendException(msg=msg)

        locations = []
        ports = self.ssh.lsnasportip()
        for port in ports:
            if port['node_name'] == node_name and port['ip'] != '':
                location = partern % {'ip': port['ip']}

                locations.append({
                    'path': location,
                    'is_admin_only': False,
                    'metadata': {}
                })

        return locations

    @staticmethod
    def access_rule_to_client_spec(access_rule):
        if access_rule['access_type'] != 'ip':
            msg = _('access type %s not support when use NFS protocol')
            raise exception.ShareBackendException(msg=msg)

        network = ipaddress.ip_network(six.text_type(access_rule['access_to']))
        if network.version != 4:
            msg = _('only IPV4 is accepted when use NFS protocol')
            raise exception.ShareBackendException(msg=msg)

        client_spec = "%(ip)s/%(mask)s:%(rights)s:all_squash:root_squash" % {
            'ip': six.text_type(network.network_address),
            'mask': six.text_type(network.netmask),
            'rights': access_rule['access_level'],
        }

        return client_spec

    def update_nfs_access(self, share_name, access_rules, add_rules,
                          delete_rules):
        """

        :param share_name:
        :param access_rules:
        :param add_rules:
        :param delete_rules:
        :return:
        """
        dirpath = self.get_dirpath_by_name(share_name)
        if not (add_rules or delete_rules):
            # first clear all
            self.ssh.rmnfs(dirpath)

            # then add all rules
            for rule in access_rules:
                client_spec = self.access_rule_to_client_spec(rule)
                self.ssh.addnfsclient(dirpath, client_spec)
        else:
            for rule in delete_rules:
                client_spec = self.access_rule_to_client_spec(rule)
                self.ssh.rmnfsclient(dirpath, client_spec)
            for rule in add_rules:
                client_spec = self.access_rule_to_client_spec(rule)
                self.ssh.addnfsclient(dirpath, client_spec)

    @staticmethod
    def access_rule_to_rights(access_rule):
        if access_rule['access_type'] != 'user':
            msg = _('access type %s not support when use CIFS protocol')
            raise exception.ShareBackendException(msg=msg)

        rights = "%(kind)s:%(name)s:%(rights)s" % {
            'kind': 'LU' if True else 'LG',
            'name': access_rule['access_to'],
            'rights': access_rule['access_level']
        }

        return rights

    def update_cifs_access(self, share_name, access_rules, add_rules,
                           delete_rules):
        """

        :param share_name:
        :param access_rules:
        :param add_rules:
        :param delete_rules:
        :return:
        """
        if not (add_rules or delete_rules):
            # TODO maybe we should only delete the users instead of the CIFS
            # first delete the share
            self.ssh.rmcifs(share_name)

            # then add the share
            dirpath = self.get_dirpath_by_name(share_name)
            self.ssh.addcifs(share_name, dirpath)

            # and last add all rules
            for rule in access_rules:
                rights = self.access_rule_to_rights(rule)
                self.ssh.addcifsuser(share_name, rights)
        else:
            for rule in delete_rules:
                rights = self.access_rule_to_rights(rule)
                self.ssh.rmcifsuser(share_name, rights)
            for rule in add_rules:
                rights = self.access_rule_to_rights(rule)
                self.ssh.addcifsuser(share_name, rights)

    @staticmethod
    def check_access_type(access_type, *rules):
        rule_chain = itertools.chain(*rules)
        if all([r['access_type'] == access_type for r in rule_chain]):
            return True
        else:
            return False

    def update_access(self, share_name, share_proto,
                      access_rules, add_rules, delete_rules):
        if share_proto == 'CIFS':
            if self.check_access_type('user', access_rules,
                                      add_rules, delete_rules):
                self.update_cifs_access(share_name, access_rules,
                                        add_rules, delete_rules)
            else:
                msg = _("Only %s access type allowed.") % "user"
                raise exception.InvalidShareAccess(reason=msg)
        elif share_proto == 'NFS':
            if self.check_access_type('ip', access_rules,
                                      add_rules, delete_rules):
                self.update_nfs_access(share_name, access_rules,
                                       add_rules, delete_rules)
            else:
                msg = _("Only %s access type allowed.") % "ip"
                raise exception.InvalidShareAccess(reason=msg)
        else:
            msg = _('share protocol %s not support') % share_proto
            raise exception.ShareBackendException(msg=msg)
