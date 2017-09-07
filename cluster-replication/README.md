Ansible Gluu Playbooks: Cluster with two main servers and LDAP replication
==========

This example deploy Gluu on 2 servers and a load balancer to dispatch requests.
The cluster-manager is optional for this example because there is only one LDAP server and the log centralization is not necessary for this example.


Vagrant Installation
-------

```
$ cd example
$ vagrant plugin install vagrant-lxc
$ vagrant plugin install vagrant-hostmanager
$ # Here, provision for gluu-nginx will fail due to the missing upstream server
$ vagrant up --provider=lxc
$ ansible-galaxy install GuillaumeSmaha.gluu-setup GuillaumeSmaha.gluu-configuration GuillaumeSmaha.gluu-customization
$ ansible-playbook -i env deploy.yml
$ # Restart servers
$ vagrant halt
$ vagrant up --provider=lxc --provision
```

Access to Gluu by going to:

https://gluu-nginx/

Exemple with implicit flow:

https://gluu-nginx/oxauth/authorize?....
