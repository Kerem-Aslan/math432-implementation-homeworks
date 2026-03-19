from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from time import perf_counter


@dataclass(frozen=True)
class PrimeCountResult:
    prime: int
    total_degree_le_5: int
    total_degree_le_4: int
    tested_quintic_parts: int
    elapsed_seconds: float


def _build_power_table(prime: int) -> tuple[list[int], list[int], list[int], list[int], list[int]]:
    elements = list(range(prime))
    x1 = elements
    x2 = [(x * x) % prime for x in elements]
    x3 = [(x2[index] * x1[index]) % prime for index in elements]
    x4 = [(x3[index] * x1[index]) % prime for index in elements]
    x5 = [(x4[index] * x1[index]) % prime for index in elements]
    return x1, x2, x3, x4, x5


def _is_permutation_without_constant(
    coefficients: tuple[int, int, int, int, int],
    prime: int,
    x1: list[int],
    x2: list[int],
    x3: list[int],
    x4: list[int],
    x5: list[int],
    precheck_points: list[int],
) -> bool:
    a5, a4, a3, a2, a1 = coefficients

    # f(0)=0 because constant term is excluded in this reduced form.
    seen_mask = 1

    for x in precheck_points:
        value = (
            a5 * x5[x]
            + a4 * x4[x]
            + a3 * x3[x]
            + a2 * x2[x]
            + a1 * x1[x]
        ) % prime
        bit = 1 << value
        if seen_mask & bit:
            return False
        seen_mask |= bit

    for x in range(1, prime):
        if x in precheck_points:
            continue
        value = (
            a5 * x5[x]
            + a4 * x4[x]
            + a3 * x3[x]
            + a2 * x2[x]
            + a1 * x1[x]
        ) % prime
        bit = 1 << value
        if seen_mask & bit:
            return False
        seen_mask |= bit

    return True


def count_permutation_polynomials_over_prime(prime: int) -> PrimeCountResult:
    started_at = perf_counter()
    elements = list(range(prime))
    x1, x2, x3, x4, x5 = _build_power_table(prime)

    # Fast reject at a few points before full scan.
    precheck_points = [point for point in (1, 2) if point < prime]

    tested_quintic_parts = 0
    total_count = 0
    leading_zero_count = 0

    for a5, a4, a3, a2, a1 in product(elements, repeat=5):
        tested_quintic_parts += 1
        if not _is_permutation_without_constant(
            (a5, a4, a3, a2, a1),
            prime,
            x1,
            x2,
            x3,
            x4,
            x5,
            precheck_points,
        ):
            continue

        # Constant term a0 can be any field element without affecting bijectivity.
        total_count += prime
        if a5 == 0:
            leading_zero_count += prime

    elapsed_seconds = perf_counter() - started_at
    return PrimeCountResult(
        prime=prime,
        total_degree_le_5=total_count,
        total_degree_le_4=leading_zero_count,
        tested_quintic_parts=tested_quintic_parts,
        elapsed_seconds=elapsed_seconds,
    )


def count_degree_five_permutation_polynomials_over_z26() -> int:
    result_mod_2 = count_permutation_polynomials_over_prime(2)
    result_mod_13 = count_permutation_polynomials_over_prime(13)

    # Use CRT and exclude the cases where the leading coefficient is 0 mod 26.
    return (
        result_mod_2.total_degree_le_5 * result_mod_13.total_degree_le_5
        - result_mod_2.total_degree_le_4 * result_mod_13.total_degree_le_4
    )


def main() -> None:
    result_mod_2 = count_permutation_polynomials_over_prime(2)
    result_mod_13 = count_permutation_polynomials_over_prime(13)
    total_z26 = (
        result_mod_2.total_degree_le_5 * result_mod_13.total_degree_le_5
        - result_mod_2.total_degree_le_4 * result_mod_13.total_degree_le_4
    )

    print(
        f"Permutation polynomials over Z2 with degree <= 5: "
        f"{result_mod_2.total_degree_le_5}"
    )
    print(
        f"Permutation polynomials over Z2 with degree <= 4: "
        f"{result_mod_2.total_degree_le_4}"
    )
    print(
        f"Permutation polynomials over Z13 with degree <= 5: "
        f"{result_mod_13.total_degree_le_5}"
    )
    print(
        f"Permutation polynomials over Z13 with degree <= 4: "
        f"{result_mod_13.total_degree_le_4}"
    )
    print(f"Permutation polynomials of degree 5 over Z26: {total_z26}")

    print()
    print(
        f"Checked {result_mod_2.tested_quintic_parts} reduced coefficient tuples over Z2 "
        f"in {result_mod_2.elapsed_seconds:.4f}s"
    )
    print(
        f"Checked {result_mod_13.tested_quintic_parts} reduced coefficient tuples over Z13 "
        f"in {result_mod_13.elapsed_seconds:.4f}s"
    )


if __name__ == "__main__":
    main()