#Prise en main 

#Question 1

La topologie utilisée s'appelle une topologie client-serveur. Il y a un serveur centre (chat_server.py) qui génére les communications entre les clients

#Question 2

Dans les logs, on remarque que les ùesssages échangés entre les clients passsent par le serveur

#Question 3

Le probleme avec cette approche c'est que si le serveur tombe en panne ou est surchargé, les clients ne pourront plus communiquer entre eux. Cela viole le principe de decentralisation

#Question 4

A la place d'une topologie client-serveur, on peut utiliser une topologie pair-à-pair(P2P). Avec la topologie P2P, les clients communique directement entre eux sans passer par un serveur central

#Chifffrement 

#Question 1 

Oui, urandom est généralement considéré comme un bon choix pour la génération de nombres aléatoires en cryptographie. C'est un bon choix pour la cryptographie en raison de sa nature imprévisible et de sa source d'entropie sécurisée.

#Question 2 
Utiliser des primitives cryptographiques peut entrainer des vulnérabilités et compromettre la sécurité du sytéme.

#Question 3 

Meme avec le chiffrement, un serveur malveillant peut représenter un risque pour plusieurs raisons. Premierement, un serveur malveillant pourrait enregistrer les métadonnées des communications meme si les messages sont chiffrés.
Deuxiémement, si le serveur reussit à obtenir les clés de chiffrement par une attaque, une négligence ou un accés non autorisé, il pourrait dechiffer les messages et acceder au contenu.
Troisiémement, un serveur malveillant pourrait manipuler ou falsifier les messages entre les clients, meme s'il ne peut pas les déchiffrer, causant ainsi des problémes de communications ou de sécurité.

#Question 4

La propriété qui manque ici est l'authentification, c'est à dire la capacité de vérifier l'identité des parties en communication et de s'assurer que les messages n'ont pas été modifiés ou falsifiés en cours de transmission.

#Authenticated Symetric Encryption 

#Question 1

Fernet est moins risqué en termes d'implémentaion car il fournit un mécanisme de chiffrement symétrique authentifié qui encapsule toutes les opérations cryptographiques requises, y compris le chiffrement, le dechiffrement et l'authentification des messages.

#Question 2 

Cette attaque est appelée "replay attack"

#Question 3 

Une methode simple pour s'en affranchir consiste à utiliser des numéros de séquence dans les messages echangés entre les parties. Chaque message reçoit un numéro de séquence unique et croissant qui est inclus dans le message avant le chiffrement et l'authentification.

#TTL

#Question 1

Dans cette implémentation, le fait d'ajouter un mécanisme de durée de vie (TTL) pour les messages signifie que si un message dépasse le TTL définit, il ne sera pas déchiffré et sera ignoré.

#Question 2 

Soustrayez 45 secondes au temps lors de l'emission signifie que le message aura deja dépassé le TTL au moment de sa réception. Par conséquent, le message sera ignoré et ne sera pas déchiffré, car le destinataire considérera qu'il a dépassé sa durée de vie.

#Question 3

Oui, c'est éfficace car un attaquant ne pourra pas réutiliser un message précédemment intercepté aprés que sa durée de vie TTL ait expiré.

#Question 4

Dans la pratique, cette solution présente certaines limites : la synchronisation de l'horloge, latence et délai de transmission, le choix du TTL, Gestion des execptions

#Regard Critique

