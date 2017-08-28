Ansible Gluu Playbooks: Signle node
==========

This example deploy Gluu on a single node.


Vagrant Installation
-------

```
$ cd example
$ vagrant plugin install vagrant-lxc
$ vagrant plugin install vagrant-hostmanager
$ vagrant up --provider=lxc
$ ansible-galaxy install GuillaumeSmaha.gluu-setup GuillaumeSmaha.gluu-configuration GuillaumeSmaha.gluu-customization
$ ansible-playbook -i env deploy.yml
```

Access to Gluu by going to:

https://gluu-single/

Exemple with implicit flow:

https://gluu-single/oxauth/authorize?....
