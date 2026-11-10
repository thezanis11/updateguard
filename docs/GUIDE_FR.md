# Comprendre et présenter UpdateGuard

## La question à maîtriser

« Comment mettre à jour un équipement sans accepter un fichier falsifié, sans revenir à une ancienne version vulnérable et sans perdre la version fonctionnelle si l'installation s'arrête ? »

Les trois questions sont différentes. Une signature authentifie des octets ; elle ne dit pas qu'ils sont récents, compatibles ou fonctionnels.

## Parcours conseillé

1. Ouvrir le rapport, comparer `replace_file_and_hash` et `replay_old_release`. Expliquer pourquoi une empreinte servie avec le fichier ne protège pas contre un serveur malveillant.
2. Lire les rôles TUF : root définit la confiance, targets décrit les fichiers autorisés, snapshot lie les versions des métadonnées, timestamp impose une fraîcheur bornée par expiration.
3. Dessiner les deux versions : version des métadonnées et version de l'application. Comprendre pourquoi un éditeur peut signer une ancienne application dans de nouvelles métadonnées.
4. Dessiner la machine d'installation : image écrite, prepared, trial, healthy, committed. Identifier exactement quand le plancher de version change.
5. Lancer les tests, puis une démonstration. Lire un résultat refusé et vérifier sa cause dans le code et le protocole.
6. Expliquer les limites : horloge, état local protégé, santé modélisée, seuil de signature un, arrêt de processus et non coupure électrique.

## Pourquoi ces choix ?

**Réutiliser python-tuf :** le projet étudie l'intégration et les hypothèses de sécurité. Réécrire un protocole cryptographique aurait créé des erreurs sans apporter une meilleure expérience.

**Deux emplacements A/B :** préparer une version candidate sans écraser immédiatement la dernière version confirmée. Le pointeur de version active et le plancher évoluent dans le même journal atomique.

**Clés temporaires :** chaque essai dispose de ses propres signatures réelles, sans clé privée persistée ni secret à distribuer.

**Pas de machine learning :** les propriétés sont des règles de protocole et des invariants d'état. Un modèle appris ne répondrait pas au problème.

**Pas de pourcentage de sécurité :** les scénarios sont choisis volontairement. Trois répétitions du même rejeu ne représentent pas trois types d'attaque ni une fréquence réelle d'attaque.

## Questions d'entretien

- Une signature valide suffit-elle ? Non : elle ne garantit ni fraîcheur, ni compatibilité, ni bon comportement.
- Que protège TUF si une clé est volée ? Cela dépend du rôle compromis et des autres clés encore fiables. Montrer les deux lignes de compromission du rapport.
- Pourquoi l'ancienne image peut-elle être utilisée après une panne ? Parce que la candidate n'est pas encore confirmée. Après confirmation et hausse du plancher, une ancienne version n'est plus acceptable comme nouvelle installation.
- Le retour de santé est-il fiable ici ? C'est une valeur synthétique, utile pour tester l'état de l'installateur. Il faut un superviseur indépendant dans un vrai équipement.
- Est-ce du secure boot ? Non. Le laboratoire ne met pas en place une racine matérielle ni une vérification de la chaîne de démarrage.
- Pourquoi vérifier par HTTP et en mémoire ? HTTP vérifie l'intégration réelle ; le transport mémoire permet des scénarios contrôlés et rapides. Ses durées ne mesurent pas un réseau réel.
- Que se passe-t-il si le serveur bloque tout ? La mise à jour échoue ; la dernière version confirmée reste disponible, mais aucune disponibilité de nouvelle version n'est garantie.

## Exercices personnels utiles

1. Avant de lancer un essai, prédire les trois décisions pour le rejeu et la rotation de clé, puis expliquer les écarts éventuels.
2. Ajouter un scénario de métadonnée manquante et vérifier que l'échec n'altère pas la version active.
3. Remplacer le booléen de santé par un petit processus local inoffensif avec délai maximal et résultat contrôlé. Documenter ce que cela ne prouve toujours pas.
4. Ajouter une rotation de clé racine avec les signatures exigées par l'ancienne et la nouvelle racine.
5. Ajouter un seuil de signature deux-sur-trois pour targets et mesurer le comportement avec une seule clé compromise.

Pour chaque exercice, conserver le résultat initial, le changement, les tests et les limites dans un court journal. Ne pas revendiquer un exercice avant de l'avoir réalisé.

## Git et GitHub simplement

Le dossier contient les fichiers de travail. Un commit est une version enregistrée du code et des résultats. Un push envoie ces commits au dépôt GitHub. Les tests GitHub reproduisent les vérifications sur des machines séparées.

Les données temporaires et l'environnement Python sont exclus. Ne pas ajouter `data/`, `.venv/`, une clé privée ou un fichier de configuration personnel pour réparer un problème de reproduction.

## Formulation CV proposée

« Projet personnel de cybersécurité : intégration de TUF et conception d'un installateur A/B simulé ; comparaison de trois politiques de vérification sur 15 scénarios et essais de récupération après interruptions de processus, avec protocole reproductible et tests automatisés. »

Cette formulation décrit le projet. Adapter les verbes au travail que vous savez expliquer et avez personnellement repris. Le développement initial a été réalisé avec assistance IA ; aucun déploiement industriel ni expérience professionnelle n'est revendiqué.
