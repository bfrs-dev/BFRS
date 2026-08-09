"""Minimal secp256k1 point operations for structural key validation."""

from typing import TypeAlias


FIELD_PRIME = (1 << 256) - (1 << 32) - 977
GROUP_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
GENERATOR_X = int(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    16,
)
GENERATOR_Y = int(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    16,
)

Point: TypeAlias = tuple[int, int] | None
GENERATOR: Point = (GENERATOR_X, GENERATOR_Y)


def is_point_on_curve(point: Point) -> bool:
    if point is None:
        return False
    x, y = point
    return (
        0 <= x < FIELD_PRIME
        and 0 <= y < FIELD_PRIME
        and pow(y, 2, FIELD_PRIME)
        == (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    )


def decode_sec_public_key(encoded: bytes) -> Point:
    if len(encoded) == 65 and encoded[0] == 4:
        point = (
            int.from_bytes(encoded[1:33], "big"),
            int.from_bytes(encoded[33:], "big"),
        )
        return point if is_point_on_curve(point) else None

    if len(encoded) != 33 or encoded[0] not in (2, 3):
        return None
    x = int.from_bytes(encoded[1:], "big")
    if x >= FIELD_PRIME:
        return None
    rhs = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y = pow(rhs, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if pow(y, 2, FIELD_PRIME) != rhs:
        return None
    if (y & 1) != (encoded[0] & 1):
        y = FIELD_PRIME - y
    point = (x, y)
    return point if is_point_on_curve(point) else None


def encode_sec_public_key(point: Point, *, compressed: bool) -> bytes:
    if not is_point_on_curve(point):
        raise ValueError("point must be a finite secp256k1 point")
    assert point is not None
    x, y = point
    x_bytes = x.to_bytes(32, "big")
    if compressed:
        return bytes((2 | (y & 1),)) + x_bytes
    return b"\x04" + x_bytes + y.to_bytes(32, "big")


def add_points(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    if not is_point_on_curve(left) or not is_point_on_curve(right):
        raise ValueError("points must lie on secp256k1")

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD_PRIME)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD_PRIME)
    slope %= FIELD_PRIME
    x3 = (slope * slope - x1 - x2) % FIELD_PRIME
    y3 = (slope * (x1 - x3) - y1) % FIELD_PRIME
    return (x3, y3)


def scalar_multiply(scalar: int, point: Point = GENERATOR) -> Point:
    if not 1 <= scalar < GROUP_ORDER:
        raise ValueError("scalar must satisfy 1 <= scalar < group order")
    if not is_point_on_curve(point):
        raise ValueError("point must be a finite secp256k1 point")

    result: Point = None
    addend = point
    multiplier = scalar
    while multiplier:
        if multiplier & 1:
            result = add_points(result, addend)
        addend = add_points(addend, addend)
        multiplier >>= 1
    return result
