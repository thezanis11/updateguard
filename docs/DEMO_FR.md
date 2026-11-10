# Démonstration en cinq minutes

Préparation : lancer `python -m updateguard.cli demo`, puis ouvrir `data/demo/index.html`. Le rapport livré sous `reports/index.html` permet aussi une présentation sans installation. Les lignes sont issues d'exécutions, pas d'une animation qui invente des résultats.

| Temps | Action | Message |
|---|---|---|
| 0:00–0:45 | Présenter le problème et les trois politiques | Authenticité, fraîcheur et récupération sont distinctes |
| 0:45–1:30 | Filtrer « replace » puis « replay » | Une empreinte modifiable ne protège pas ; une ancienne signature peut rester valide |
| 1:30–2:15 | Filtrer « key » | Montrer la rotation légitime, la révocation et la limite avec toutes les clés en ligne compromises |
| 2:15–3:30 | Lire les cinq lignes de récupération | Avant santé persistée : v1. Après : v2. Le processus a réellement été interrompu |
| 3:30–4:15 | Expliquer `health failure` | Un fichier authentique peut être défectueux ; le test d'installation conserve v1 |
| 4:15–5:00 | Montrer les coûts et les limites | Transport mémoire, logiciel simulé, aucune garantie de coupure électrique ou de secure boot |

Pour une démonstration technique plus longue : exécuter `python -m unittest discover -s tests -v` et commenter les tests HTTP, version-floor ablation et unhealthy signed update.
