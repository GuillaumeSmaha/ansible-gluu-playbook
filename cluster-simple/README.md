Ansible Gluu Playbooks: Cluster with one main node and few consumers
==========

This example deploy Gluu on 2 servers and a load balancer to dispatch requests.
The cluster-manager is optional for this example because there is only one LDAP server and the log centralization is not necessary for this example.


Vagrant Installation
-------

```
$ cd example
$ vagrant plugin install vagrant-hostmanager
$ # Here, provision for gluu-nginx will fail due to the missing upstream server
$ vagrant up
$ ansible-galaxy install GuillaumeSmaha.gluu-setup GuillaumeSmaha.gluu-configuration GuillaumeSmaha.gluu-customization
$ ansible-playbook -i env deploy.yml
$ # Restart servers
$ vagrant halt
$ vagrant up --provision
```

Access to Gluu by going to:

https://gluu-nginx/

Exemple with implicit flow:

https://gluu-nginx/oxauth/authorize?....
