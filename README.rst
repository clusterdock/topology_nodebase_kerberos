=================================
nodebase topology for clusterdock
=================================

This repository houses the **nodebase kerberos** topology for `clusterdock`_.

.. _clusterdock: https://github.com/clusterdock/clusterdock

Usage
=====

Assuming you've already installed **clusterdock** (if not, go `read the docs`_),
you use this topology by cloning it to a local folder and then running commands
with the ``clusterdock`` script:

.. _read the docs: http://clusterdock.readthedocs.io/en/latest/

.. code-block:: console

    $ git clone https://github.com/clusterdock/topology_nodebase_kerberos.git
    $ clusterdock start topology_nodebase_kerberos
    2017-09-20 09:29:53 PM clusterdock.models   INFO     Starting cluster on network (cluster) ...
    2017-09-20 09:29:53 PM clusterdock.models   INFO     Starting node kdc.cluster ...
    2017-09-20 09:29:54 PM clusterdock.models   INFO     Starting node node-1.cluster ...
    2017-09-20 09:29:55 PM clusterdock.models   INFO     Starting node node-2.cluster ...
    2017-09-20 09:29:55 PM clusterdock.topology_nodebase_kerberos.start INFO     Updating KDC configurations ...
    2017-09-20 09:29:57 PM clusterdock.topology_nodebase_kerberos.start INFO     Starting KDC ...
    2017-09-20 09:29:59 PM clusterdock.topology_nodebase_kerberos.start INFO     Validating service health ...
    2017-09-20 09:29:59 PM clusterdock.cli      INFO     Cluster started successfully (total time: 0m 5s).

To see full usage instructions for the ``start`` action, use ``-h``/``--help``:

.. code-block:: console

    $ clusterdock start topology_nodebase_kerberos -h
    usage: clusterdock start [--always-pull] [--namespace ns] [--network nw]
                             [-o sys] [-r url] [-h]
                             [--kerberos-config-directory KERBEROS_CONFIG_DIRECTORY]
                             [--kerberos-principals princ1,princ2,...]
                             [--node-disks map] [--kdc-node node [node ...]]
                             [--nodes node [node ...]]
                             topology

    Start a nodebase_kerberos cluster

    positional arguments:
      topology              A clusterdock topology directory

    optional arguments:
      --always-pull         Pull latest images, even if they're available locally
                            (default: False)
      --namespace ns        Namespace to use when looking for images (default:
                            None)
      --network nw          Docker network to use (default: cluster)
      -o sys, --operating-system sys
                            Operating system to use for cluster nodes (default:
                            centos6.6)
      -r url, --registry url
                            Docker Registry from which to pull images (default:
                            docker.io)
      -h, --help            show this help message and exit

    nodebase_kerberos arguments:
      --kerberos-config-directory path
                            If specified, mounts this directory to KDC container
                            for Kerberos config files. (default:
                            ~/.clusterdock/kerberos)
      --kerberos-principals princ1,princ2,...
                            If specified, a comma-separated list of Kerberos user
                            principals to create in KDC. (default: None)

    Node groups:
      --kdc-node node [node ...]
                            Nodes of the kdc-node group (default: ['kdc'])
      --nodes node [node ...]
                            Nodes of the nodes group (default: ['node-1',
                            'node-2'])
