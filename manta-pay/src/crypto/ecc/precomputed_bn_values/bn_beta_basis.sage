# BN254 parameters taken from https://neuromancer.sk/std/bn/bn254.

p = 0x2523648240000001BA344D80000000086121000000000013A700000000000013
K = GF(p)
a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
b = K(0x0000000000000000000000000000000000000000000000000000000000000002)
E = EllipticCurve(K, (a, b))
G = E(0x2523648240000001BA344D80000000086121000000000013A700000000000012, 0x0000000000000000000000000000000000000000000000000000000000000001)
order_subgroup = 0x2523648240000001BA344D8000000007FF9F800000000010A10000000000000D
cofactor = 0x01
E.set_order(0x2523648240000001BA344D8000000007FF9F800000000010A10000000000000D * 0x01)
EK = GF(order_subgroup)

def generate_cubic_root(field):
    # Given a finite field, its primitive cubic roots of unity.
    R.<x> = field[] 
    f = x^2+x+1
    return [f.roots()[0][0], f.roots()[1][0]]

def endomorphism(E, P, factor):
    # Multiplies the x-coordinate of the point `P` on the elliptic curve `E` by `factor`.
    return E(factor*P[0], P[1], P[2])

def valid_pair(beta_values, lambda_values, E, P, b=1):
    # It returns the [`beta_value`, `lambda_value`] valid pair corresponding to 
    # the largest `lambda`. If `b=0`, it returns the other valid pair.
    if b:
        lambda_value = max(lambda_values)
    else: 
        lambda_value = min(lambda_values)
    for beta_value in beta_values:
        if endomorphism(E, P, beta_value) == lambda_value*P:
            return [beta_value, lambda_value]

def shorter(v, u):
    # Returns the shorter of the two vectors in the L2 norm.
    if sqrt(v[0]*v[0] + v[1]*v[1]) < sqrt(u[0]*u[0] + u[1]*u[1]):
        return v
    else:
        return u; 

def generate_short_basis(n, l):
    # Generates a basis of short vectors in Z^2 for the kernel of the map
    # (i, j) -> i+l*j (mod n)
    next_r, r = l, n
    next_t, t = 1, 0

    while r >= sqrt(n):
        v2 = [r, -t]
        q = r // next_r
        r, next_r = next_r, r - q*next_r
        t, next_t = next_t, t - q*next_t
    v1 = [r, -t]
    v2 = shorter(v2, [next_r, -next_t])
    return (v1, v2)

def print_for_rust():
    # Prints `beta` and `basis` as a rust array
    beta_values = generate_cubic_root(K)
    lambda_values = generate_cubic_root(EK)
    pair = valid_pair(beta_values, lambda_values, E, G)
    basis = generate_short_basis(order_subgroup, int(pair[1]))
    print([str(pair[0]), str(basis[0][0]), str(basis[0][1]), str(basis[1][0]), str(basis[1][1])])
def main():
    print_for_rust()

if __name__ == '__main__':
    main()
