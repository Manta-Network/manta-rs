# BLS12-381 parameters taken from https://neuromancer.sk/std/bls/BLS12-381.

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
a = K(0x00)
b = K(0x04)
E = EllipticCurve(K, (a, b))
G = E(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB, 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
order_subgroup = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
cofactor = 0x396C8C005555E1568C00AAAB0000AAAB
E.set_order(order_subgroup * cofactor)
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
    # Prints `beta` and `basis` in five lines
    beta_values = generate_cubic_root(K)
    lambda_values = generate_cubic_root(EK)
    pair = valid_pair(beta_values, lambda_values, E, G)
    basis = generate_short_basis(order_subgroup, int(pair[1]))
    output = [pair[0], basis[0][0], basis[0][1], basis[1][0], basis[1][1]]
    print("[\"" + '\", \"'.join(f'{w}' for w in output) + "\"]")

def main():
    print_for_rust()

if __name__ == '__main__':
    main()
