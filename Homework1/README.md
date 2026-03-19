# Homework 1

This folder contains Python solutions for two questions.

## Files

- `frequency_analysis.py`: letter frequency analysis and monoalphabetic cipher decryption
- `permutation_polynomials_z26.py`: counts degree-5 permutation polynomials over Z26
- `samples/plain_english.txt`: sample English plaintext
- `samples/cipher_english.txt`: sample English ciphertext
- `samples/plain_turkish.txt`: sample Turkish plaintext
- `samples/cipher_turkish.txt`: sample Turkish ciphertext

## 1. Question: Frequency Analysis

The script supports two languages:

- `english`
- `turkish`

You can run the commands inside the `Homework1` folder.

### English text frequency analysis

```powershell
python frequency_analysis.py analyze samples/plain_english.txt --language english
```

### Turkish text frequency analysis

```powershell
python frequency_analysis.py analyze samples/plain_turkish.txt --language turkish
```

### Decrypting the English ciphertext

```powershell
python frequency_analysis.py decrypt samples/cipher_english.txt --language english
```

### Decrypting the Turkish ciphertext

```powershell
python frequency_analysis.py decrypt samples/cipher_turkish.txt --language turkish
```

The `decrypt` command directly builds an estimated mapping based on frequency order.

## 2. Question: Degree-5 Permutation Polynomials over Z26

To run:

```powershell
python permutation_polynomials_z26.py
```

The program first counts the valid cases over Z2 and Z13. It then computes the result for Z26 using the Chinese Remainder Theorem.

## Note

All sample files are saved with UTF-8 encoding.
The Turkish sample texts intentionally include the letters `ç, ğ, ı, İ, ö, ş, ü`.