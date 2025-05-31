# SuperNanny  
Master Project ISEN 2024/2025

## Déploiement du backend SuperNanny sur un cluster Kubernetes

### Qu'est-ce que Docker ?  

Docker est une plateforme qui permet de créer, déployer et exécuter des applications dans des conteneurs. Un conteneur est un environnement léger, isolé et portable qui contient tout ce dont une application a besoin pour fonctionner (code, bibliothèques, dépendances).

### Qu'est-ce qu'une image Docker ?  

Une image Docker est un modèle immuable qui contient tous les fichiers, configurations et dépendances nécessaires pour créer un conteneur. C’est comme un instantané de l’environnement d’une application, prêt à être lancé.

### À quoi ça sert de faire des images sur Docker ?  

Créer des images Docker permet de garantir que l’application fonctionnera de manière identique partout, quel que soit l’environnement (local, serveur, cloud). Cela facilite le déploiement, la distribution et la gestion des applications, tout en assurant leur portabilité et leur reproductibilité.

### Qu'est-ce que Kubernetes et pourquoi l'utiliser ###

Kubernetes est une plateforme open source qui automatise le déploiement, la gestion et la mise à l’échelle des applications conteneurisées. Il orchestre les conteneurs (comme ceux créés avec Docker) pour garantir leur disponibilité, leur résilience et leur performance dans des environnements de production.  
Il permet de gérer facilement des applications complexes composées de plusieurs conteneurs, en automatisant la mise à jour, la récupération après panne, la répartition de charge, et la montée en charge. Cela simplifie l'exploitation, améliore la fiabilité, et facilite la scalabilité des applications dans des environnements cloud ou hybrides.  
L'objectif ici est de permettre aux entreprises d'utiliser SuperNanny, peu importe leur nombre d'employés, et de faire en sorte qu'il soit utilisable sans interruption.

#### Prérequis ####

Il est nécessaire d'installer Ansible pour déployer ce projet.  
Vous pouvez suivre les indications en fonction de votre distribution en [cliquant ici](https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html).

#### Master Node ####  
Créez une première VM Linux, voici les configurations minimales nécessaires :  

- 2 vCPU  
- 4 Go RAM  
- 20 Go disque  

Une fois créée :  

```ansible-playbook masternode.yaml --ask-become-pass```  

Voilà, votre master node est créé.  

Il est nécessaire que vous sauvegardiez les données affichées dans la tâche _Données sensibles à conserver_. Nous vous expliquons où les conserver dans la section suivante.

#### Ansible Vault ####

Pour continuer, vous devez créer une nouvelle VM Linux. Cette nouvelle VM sera votre worker node. Les configurations minimales nécessaires sont :  
- 2 vCPU  
- 4 Go RAM  
- 20 Go disque  

Lors de la création du master node, vous avez obtenu quelques valeurs sensibles.  

```kubeadm join <MASTER_IP>:6443 --token <TOKEN> --discovery-token-ca-cert-hash sha256:<HASH>```  

Vous pouvez, si vous le souhaitez, utiliser Ansible Vault pour les stocker en utilisant les commandes suivantes :  

```ansible-vault create secret.yaml```  

Un mot de passe vous sera demandé. Souvenez-vous-en, il vous permettra de modifier et supprimer le fichier si nécessaire.

Une fois le mot de passe entré, saisissez ces lignes :  

```master_address: "<MASTER_IP>"```  

```kubeadm_token: "<TOKEN>"```  

```ca_cert_hash: "<votre HASH>"```  

> Attention ! Si vous n'utilisez pas les mêmes noms de variables que celles-ci, votre worker node ne fonctionnera pas. Ou bien modifiez l'appel des variables dans le playbook workernode.  

- Si vous ne vous souvenez pas de ces informations, vous pouvez, sur votre master node, taper la commande :  

```kubeadm token create --print-join-command```  

- Si vous avez fait une erreur lors de la saisie, vous pouvez utiliser : ```ansible-vault edit secret.yaml```  

> Si vous ne souhaitez pas utiliser Ansible Vault, vous devrez modifier la ligne kubeadm join du playbook workernode Ansible.

#### Worker Node ####

Commencez par créer le répertoire .kube dans le répertoire courant de l'utilisateur :  

```mkdir .kube```  

Il vous sera nécessaire de copier le fichier admin.conf du master node vers votre worker node dans le dossier créé précédemment. Pour ce faire, utilisez la commande suivante :  

```scp utilisateur@adresse_ip:/etc/kubernetes/admin.conf ~/.kube/config```  

Si vous avez bien suivi les étapes précédentes, il ne vous reste plus qu'à lancer le playbook _workernode.yaml_ en utilisant la commande suivante :  

```ansible-playbook worker.yaml --ask-become-pass --ask-vault-pass```  

Saisissez votre mot de passe utilisateur pour devenir root, puis celui que vous avez utilisé pour Ansible Vault. Enfin, laissez l'exécution aller au bout.  

Bravo, le backend SuperNanny est déployé sur un cluster Kubernetes.
