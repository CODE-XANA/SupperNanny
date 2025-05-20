# SupperNanny
Master Project ISEN 2024/2025

## Déploiment du backend SuperNanny sur un cluster Kubernetes

#### Prérequis ####

Il est nécessaire d'installer Ansible pour déployer ce projet. 
Vous pouvez suivre les indications en fonction de votre distribution en [cliquant ici](https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html).

#### Master Node ####
Créez une première VM linux, voici les configurations minimum nécessaire : 

- 2 vCPU
- 4 Go RAM 
- 20 Go disque

Une fois créé : 

```ansible-playbook masternode.yaml --ask-become-pass```

Voilà votre master node est créé. 

Il est nécessaire que vous sauvegardiez les données affichées dans la tâche _Données sensibles à conserver_. Nous vous expliquons ou les conserver dans la section suivante. 

#### Ansible Vault ####

Pour continuer, vous devez créer une nouvelle VM linux. Cette nouvelle VM sera votre worker node. 

Lors de la création du master node, vous avez obtenu quelques valeurs sensibles. 

```kubeadm join <MASTER_IP>:6443 --token <TOKEN> --discovery-token-ca-cert-hash sha256:<HASH>```

Vous pouvez, si vous le souhaitez utiliser ansible vault pour les stocker en utilisant les commandes suivantes : 

```ansible-vault create secret.yaml```

Un mot de passe vous sera demandé. Souvenez-vous en, il vous permettra de modifier et supprimer le fichier si nécessaire.

Une fois le mot de passe entré, saisissez ces lignes : 

```master_address: "<MASTER_IP>"```

```kubeadm_token: "<TOKEN>"```

```ca_cert_hash: "<votre HASH>"```

> Attention ! Si vous n'utilisez pas les mêmes noms de variables que celles ci-dessus, votre worker node ne fonctionnera pas. Ou bien modifiez l'appel des variables dans le playbook workernode. 

- Si vous ne vous souvenez pas de ces informations vous pouvez sur votre master node taper la commande :

```kubeadm token create --print-join-command```

- Si vous avez fait une erreur lors de la saisie, vous pouvez utiliser : ```ansible-vault edit secret.yaml```

> Si vous ne souhaitez pas utiliser Ansible Vault, vous devrez modifier la ligne kubeadm join du playbook workernode ansible.

#### Worker Node ####

Si vous avez bien suivi les étapes précédentes il ne vous reste plus qu'à lancer le playbook _workernode.yaml_ en utilisant la commande suivante : 

```ansible-playbook workernode.yaml --ask-become-pass --ask-vault-pass```

Saississez votre mot de passe utilisateur pour devenir root, puis celui que vous avez utilisé pour ansible Vault. Enfin, laissez l'execution allez au bout. 

Bravo, le backend SuperNanny est déployé sur un cluster Kubernetes. 
