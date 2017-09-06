Ansible Gluu Playbooks
==========

This repository provides few examples of playbooks to deploy Gluu.


These examples use the following roles:

- https://github.com/GuillaumeSmaha/ansible-role-gluu-cluster-manager
- https://github.com/GuillaumeSmaha/ansible-role-gluu-setup
- https://github.com/GuillaumeSmaha/ansible-role-gluu-configuration
- https://github.com/GuillaumeSmaha/ansible-role-gluu-customization



Playbooks
-------

- [Single node](./single)
- [Cluster with one main node and few consumers](./cluster-simple)
- [Cluster with two main servers and LDAP replication](./cluster-replication)