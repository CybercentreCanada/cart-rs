# CaRT (Compressed and RC4 Transport)

The CaRT file format is used to store/transfer malware and it's associated metadata. It neuters the malware so it cannot be executed and encrypt it so anti-virus softwares cannot flag the CaRT file as malware.

## Library

This crate provides methods to encode and decode the CaRT format (which can be used directly) and exports them into a C library.

## Details

For more details about how the CaRT format is implemented or ways it can be used check it's original implementation: https://github.com/CybercentreCanada/cart

----------

# CaRT (Compressed and RC4 Transport)

Le format de fichier CaRT permet de stocker et de transférer les maliciels et les métadonnées connexes. Il neutralise les maliciels de manière à ce qu’ils puissent être exécutés et chiffrés pour que le logiciel antivirus ne signale pas le fichier CaRT comme étant un maliciel.

## Une bibliothèque

Ce crate fournit des méthodes pour encoder et décoder le format CaRT (qui peut être utilisé directement) et les exporte dans une bibliothèque C.

## Des détails

Pour plus de détails sur la façon dont le format CaRT est implémenté ou comment il peut être utilisé, vérifiez son implémentation d'origine: https://github.com/CybercentreCanada/cart
