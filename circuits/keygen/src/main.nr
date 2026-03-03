use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

fn main(priv_lo: Field, priv_hi: Field) -> pub (Field, Field) {
    let privkey = EmbeddedCurveScalar { lo: priv_lo, hi: priv_hi };

    let pubkey = fixed_base_scalar_mul(privkey);

    (pubkey.x, pubkey.y)
}
