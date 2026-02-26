use dep::poseidon::poseidon2::Poseidon2;

global TREE_DEPTH: u32 = 20;

pub fn compute_merkle_root(
    leaf: Field,
    path: [Field; TREE_DEPTH],
    path_index_bits: [bool; TREE_DEPTH],
) -> Field {
    let mut current = leaf;

    for i in 0..TREE_DEPTH {
        if path_index_bits[i] {
            current = Poseidon2::hash([path[i], current], 2);
        } else {
            current = Poseidon2::hash([current, path[i]], 2);
        }
    }

    current
}

pub fn assert_membership(
    root: Field,
    leaf: Field,
    path: [Field; TREE_DEPTH],
    path_index_bits: [bool; TREE_DEPTH],
) {
    let calculated_root = compute_merkle_root(leaf, path, path_index_bits);
    assert(calculated_root == root);
}
