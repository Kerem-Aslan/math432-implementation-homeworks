from __future__ import annotations

import argparse
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass(frozen=True)
class LanguageConfig:
    alphabet: str
    frequency_order: str
    upper_map: Dict[str, str]
    lower_map: Dict[str, str]


LANGUAGE_CONFIGS = {
    "english": LanguageConfig(
        alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        frequency_order="ETAOINSHRDLCUMWFGYPBVKJXQZ",
        upper_map={},
        lower_map={},
    ),
    "turkish": LanguageConfig(
        alphabet="ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ",
        frequency_order="AEİNRLIKDMUYTSBOÜŞZGÇHCPVĞFJÖ",
        upper_map={"i": "İ", "ı": "I"},
        lower_map={"I": "ı", "İ": "i"},
    ),
}


def read_text_file(path: str) -> str:
    return unicodedata.normalize("NFC", Path(path).read_text(encoding="utf-8"))


def get_language_config(language_name: str) -> LanguageConfig:
    return LANGUAGE_CONFIGS[language_name]


def to_upper(character: str, config: LanguageConfig) -> str:
    normalized = unicodedata.normalize("NFC", character)
    return config.upper_map.get(normalized, normalized.upper())


def to_lower(character: str, config: LanguageConfig) -> str:
    normalized = unicodedata.normalize("NFC", character)
    return config.lower_map.get(normalized, normalized.lower())


def count_letters(text: str, config: LanguageConfig) -> Counter[str]:
    letters = [
        upper_character
        for character in text
        for upper_character in [to_upper(character, config)]
        if upper_character in config.alphabet
    ]
    return Counter(letters)


def compute_frequencies(text: str, config: LanguageConfig) -> Dict[str, float]:
    counts = count_letters(text, config)
    total_letters = sum(counts.values())
    if total_letters == 0:
        return {letter: 0.0 for letter in config.alphabet}
    return {
        letter: (counts.get(letter, 0) / total_letters) * 100
        for letter in config.alphabet
    }


def print_frequency_table(text: str, config: LanguageConfig) -> None:
    counts = count_letters(text, config)
    frequencies = compute_frequencies(text, config)
    total_letters = sum(counts.values())
    alphabet_positions = {
        letter: index for index, letter in enumerate(config.alphabet)
    }

    print(f"Total letters: {total_letters}")
    print("Letter  Count  Frequency(%)")
    for letter in sorted(
        config.alphabet,
        key=lambda item: (-counts.get(item, 0), alphabet_positions[item]),
    ):
        print(f"{letter:>6}  {counts.get(letter, 0):>5}  {frequencies[letter]:>11.2f}")


def build_frequency_guess(text: str, config: LanguageConfig) -> Dict[str, str]:
    counts = count_letters(text, config)
    alphabet_positions = {
        letter: index for index, letter in enumerate(config.alphabet)
    }
    ranked_letters = sorted(
        config.alphabet,
        key=lambda item: (-counts.get(item, 0), alphabet_positions[item]),
    )
    return {
        cipher_letter: plain_letter
        for cipher_letter, plain_letter in zip(ranked_letters, config.frequency_order)
    }


def decrypt_text(text: str, mapping: Dict[str, str], config: LanguageConfig) -> str:
    decrypted_characters = []
    for character in text:
        upper_character = to_upper(character, config)
        if upper_character in mapping:
            plain_character = mapping[upper_character]
            decrypted_characters.append(
                plain_character if character == upper_character else to_lower(plain_character, config)
            )
        else:
            decrypted_characters.append(character)
    return "".join(decrypted_characters)


def print_mapping(mapping: Dict[str, str], config: LanguageConfig) -> None:
    print("Cipher -> Plain")
    for cipher_letter in config.alphabet:
        if cipher_letter not in mapping:
            continue
        print(f"{cipher_letter} -> {mapping[cipher_letter]}")


def add_language_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--language",
        default="english",
        choices=sorted(LANGUAGE_CONFIGS),
        help="Alphabet and frequency order to use",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Frequency analysis and monoalphabetic cipher decryption"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Show letter frequencies")
    analyze_parser.add_argument("input_file", help="Path to the input text file")
    add_language_argument(analyze_parser)

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a monoalphabetic cipher text"
    )
    decrypt_parser.add_argument("input_file", help="Path to the cipher text file")
    add_language_argument(decrypt_parser)

    return parser


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args()
    text = read_text_file(args.input_file)
    config = get_language_config(args.language)

    if args.command == "analyze":
        print_frequency_table(text, config)
        return

    print_frequency_table(text, config)
    print()

    mapping = build_frequency_guess(text, config)
    print("Using frequency-based guess.")

    print_mapping(mapping, config)
    print()
    print("Decrypted text:")
    print(decrypt_text(text, mapping, config))


if __name__ == "__main__":
    main()