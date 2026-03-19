# Homework 1

Bu klasör iki soru için Python çözümlerini içerir.

## Dosyalar

- `frequency_analysis.py`: harf frekansı analizi ve monoalphabetic cipher çözümleme
- `permutation_polynomials_z26.py`: Z26 üzerinde derece 5 permütasyon polinomlarını sayar
- `samples/plain_english.txt`: İngilizce düz metin örneği
- `samples/cipher_english.txt`: İngilizce şifreli metin örneği
- `samples/plain_turkish.txt`: Türkçe düz metin örneği
- `samples/cipher_turkish.txt`: Türkçe şifreli metin örneği

## 1. Soru: Frequency Analysis

Script iki dil destekler:

- `english`
- `turkish`

Komutları `Homework1` klasörü içinde çalıştırabilirsiniz.

### İngilizce metin frekans analizi

```powershell
python frequency_analysis.py analyze samples/plain_english.txt --language english
```

### Türkçe metin frekans analizi

```powershell
python frequency_analysis.py analyze samples/plain_turkish.txt --language turkish
```

### İngilizce şifreli metni çözme

```powershell
python frequency_analysis.py decrypt samples/cipher_english.txt --language english
```

### Türkçe şifreli metni çözme

```powershell
python frequency_analysis.py decrypt samples/cipher_turkish.txt --language turkish
```

`decrypt` komutu doğrudan frekans sırasına göre tahmini eşleme kurar.

## 2. Soru: Z26 Üzerinde Derece 5 Permütasyon Polinomları

Çalıştırmak için:

```powershell
python permutation_polynomials_z26.py
```

Program önce Z2 ve Z13 üzerindeki geçerli durumları sayar. Sonra Chinese Remainder Theorem kullanarak Z26 sonucunu hesaplar.

## Not

Tüm örnek dosyalar UTF-8 kodlaması ile kaydedildi.
Türkçe örnek metinlerde `ç, ğ, ı, İ, ö, ş, ü` harfleri özellikle yer alır.