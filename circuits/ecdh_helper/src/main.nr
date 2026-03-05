use ::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul};

fn main(
    audit_pub_x: Field,
    audit_pub_y: Field,
    ephemeral_priv_lo: u128,
    ephemeral_priv_hi: u128,
) -> pub (Field, Field, Field) {
    let ephemeral_scalar =
        EmbeddedCurveScalar { lo: ephemeral_priv_lo as Field, hi: ephemeral_priv_hi as Field };

    let ephemeral_pub = fixed_base_scalar_mul(ephemeral_scalar);

    let audit_pub_point = EmbeddedCurvePoint { x: audit_pub_x, y: audit_pub_y, is_infinite: false };
    let shared_audit_point = multi_scalar_mul([audit_pub_point], [ephemeral_scalar]);
    let k_audit = Poseidon2::hash([shared_audit_point.x, shared_audit_point.y], 2);

    (ephemeral_pub.x, ephemeral_pub.y, k_audit)
}
