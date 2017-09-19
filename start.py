# -*- coding: utf-8 -*-
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

import logging
import re
from os.path import expanduser

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

logger = logging.getLogger('clusterdock.{}'.format(__name__))

DEFAULT_OPERATING_SYSTEM = 'centos6.6'

KDC_ACL_FILENAME = '/var/kerberos/krb5kdc/kadm5.acl'
KDC_CONF_FILENAME = '/var/kerberos/krb5kdc/kdc.conf'
KERBEROS_VOLUME_DIR = '/etc/clusterdock/kerberos'
KDC_KEYTAB_FILENAME = '{}/clusterdock.keytab'.format(KERBEROS_VOLUME_DIR)
KDC_KRB5_CONF_FILENAME = '/etc/krb5.conf'


def main(args):
    image = '{}/{}/topology_nodebase:{}'.format(args.registry,
                                                args.namespace,
                                                args.operating_system or DEFAULT_OPERATING_SYSTEM)
    nodes = [Node(hostname=hostname, group='nodes', image=image)
             for hostname in args.nodes]

    kerberos_volume_dir = args.kerberos_config_directory.replace('~', expanduser('~'))
    kdc_image = '{}/{}/topology_nodebase_kerberos:{}'.format(args.registry,
                                                             args.namespace,
                                                             args.operating_system or DEFAULT_OPERATING_SYSTEM)
    kdc_hostname = args.kdc_node[0]
    kdc_node = Node(hostname=kdc_hostname, group='kdc', image=kdc_image,
                    volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}])
    cluster = Cluster(kdc_node, *nodes)
    cluster.start(args.network)

    logger.info('Updating KDC configurations ...')
    realm = cluster.network.upper()
    # Update configurations
    krb5_conf_data = kdc_node.get_file(KDC_KRB5_CONF_FILENAME)
    kdc_node.put_file(KDC_KRB5_CONF_FILENAME,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'example.com', cluster.network,
                                    re.sub(r'kerberos.example.com', r'{}.{}'.format(kdc_hostname, cluster.network),
                                           krb5_conf_data))))
    kdc_conf_data = kdc_node.get_file(KDC_CONF_FILENAME)
    kdc_node.put_file(KDC_CONF_FILENAME,
                      re.sub(r'EXAMPLE.COM', realm,
                             kdc_conf_data.replace(r'[kdcdefaults]',
                                                   '[kdcdefaults]\n max_renewablelife = 7d\n max_life = 1d')))
    acl_data = kdc_node.get_file(KDC_ACL_FILENAME)
    kdc_node.put_file(KDC_ACL_FILENAME, re.sub(r'EXAMPLE.COM', realm, acl_data))

    kdc_commands = [
        'kdb5_util create -s -r {realm} -P kdcadmin'.format(realm=realm),
        'kadmin.local -q "addprinc -pw {adminpw} admin/admin@{realm}"'.format(adminpw='acladmin', realm=realm)
    ]

    logger.info('Starting KDC ...')
    # Add the following commands before starting kadmin daemon etc.
    if args.kerberos_principals:
        principal_list = ['{}@{}'.format(primary, realm) for primary in args.kerberos_principals.split(',')]
        create_principals_cmds = ['kadmin.local -q "addprinc -randkey {}"'.format(principal)
                                  for principal in principal_list]
        kdc_commands.extend(create_principals_cmds)

        create_keytab_cmd = 'kadmin.local -q "xst -norandkey -k {} {}" '.format(KDC_KEYTAB_FILENAME,
                                                                                ' '.join(principal_list))
        kdc_commands.append(create_keytab_cmd)

    kdc_commands.extend([
        'krb5kdc',
        'kadmind',
        'authconfig --enablekrb5 --update',
        'service sshd start',
        'service krb5kdc start',
        'service kadmin start'
    ])

    # Gather keytab file and krb5.conf file in KERBEROS_VOLUME_DIR directory which is mounted on host.
    kdc_commands.append('cp {} {}'.format(KDC_KRB5_CONF_FILENAME, KERBEROS_VOLUME_DIR))
    if args.kerberos_principals:
        kdc_commands.append('chmod 644 {}'.format(KDC_KEYTAB_FILENAME))

    kdc_node.execute(command="bash -c '{}'".format('; '.join(kdc_commands)), quiet=True)

    logger.info('Validating service health ...')
    _validate_service_health(node=kdc_node, services=['sshd', 'krb5kdc', 'kadmin'])


def _validate_service_health(node, services):
    def condition(node, services):
        if all('is running' in (node.execute(command='service {} status'.format(service), quiet=True).output)
               for service in services):
            return True
        else:
            logger.debug('Services with poor health: %s',
                         ', '.join(service
                                   for service in services
                                   if 'is running' not in node.execute(command='service {} status'.format(service),
                                                                       quiet=True).output))

    def success(time):
        logger.debug('Validated service health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate service health.'.format(timeout))
    wait_for_condition(condition=condition, condition_args=[node, services],
                       time_between_checks=3, timeout=600, success=success, failure=failure)
