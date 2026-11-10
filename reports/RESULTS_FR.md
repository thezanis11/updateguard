# Résultats mesurés — UpdateGuard

Date UTC : 2026-11-10T13:28:18.726486+00:00

- 135 décisions de vérification : toutes conformes aux attentes = True.
- 30 interruptions réelles de processus : invariants de récupération respectés = True.
- Durée de campagne : 29.01 secondes.

## Ce que montrent les expériences

Le rejeu passe les références empreinte et signature unique, mais est refusé par le client TUF avec état persistant.
La rotation de clé est acceptée par TUF ; le client à clé fixe refuse la nouvelle signature.
La compromission de toutes les clés en ligne reste acceptée : c'est une limite explicite de la configuration, pas une attaque bloquée.
Une image authentique peut être malsaine. La vérification et la récupération sont des responsabilités séparées.
Avant confirmation de santé, le redémarrage conserve v1. Après persistance de la santé, il termine v2.

## Limites

Les répétitions servent à observer les durées, pas à multiplier le nombre de menaces indépendantes.
Les attaques sont des scénarios construits. Aucun taux de risque réel ni intervalle de confiance de sécurité n'est déduit.
Le test de récupération interrompt le processus aux frontières persistantes ; il ne simule pas les défaillances électriques d'une mémoire flash.
Les résultats ont été consultés pendant le développement : étude exploratoire, sans test aveugle.
