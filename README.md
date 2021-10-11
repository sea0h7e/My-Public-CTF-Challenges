# My-Public-CTF-Challenges
This is the repository of some CTF challenges I made, maybe including the source code and solution.

## **ToC**

- [0CTF/TCTF 2021 Finals](#0CTF/TCTF-2021-Finals)
  - [ezMat](#ezMat)
  - [ezHash](#ezHash)
  - [ezRSA](#ezRSA)
  - [ezRSA+](#ezRSA+)
  - [halfhalf](#halfhalf)
- [0CTF/TCTF 2021 Quals](#0CTF/TCTF-2021-Quals)
  - [zer0lfsr-](#zer0lfsr-)
  - [zer0lfsr+](#zer0lfsr+)
  - [zer0lfsr++](#zer0lfsr++)

<a id="0CTF/TCTF-2021-Finals"></a>
## 0CTF/TCTF 2021 Finals

### ezMat
Category: **Crypto**  
Difficulty: ★  
Solved: **12 / 12**  
Tag: **Matrix, Linear Algebra**  

#### Details

[Source](0CTF-TCTF-2021-Finals/ezMat/)

This task is inspired from the challenge [**Onclude**](https://ctftime.org/task/16872) in *Crypto CTF 2021*. 
The ciphertext computes as `E = L_inv * S * X = U * X = U * (A + R)`, we know `E` and `R`, need to recover `A`. And `U` is the LU decomposition of a secret matrix, `A` is a matrix which contains most of zero and flag bytes. We are also given a sha256 digest of flag.

#### Solution

Notice that `U` is a triangular matrix, and there are lots of zero elements in `A`, thus we may solve linear equations to recover most elements in `A`,  then bruteforce the remaining bytes according to the given sha256 digest.

### ezHash
Category: Crypto  
Difficulty: ★★★☆  
Solved: **3 / 12**  
Tag: **Matrix, LPS Graph**  

#### Details

[Source](0CTF-TCTF-2021-Finals/ezHash/)

The script implements an algorithm involves 2x2 matrix multiplication over Fp. Our input will be converted to base 5 sequence, then each time choose one of the six generator matrix multiple to the result according to the sequence.
The server will generate a random matrix `X` per connection, we have 10 seconds to find an input which yields a matrix `Y`, where `Y ≡ aX (mod p)` for some `a ∈ Fp`.

#### Solution
In fact, the algorithm is a hash function based on LPS graph. This paper [[1]](#ezHash-ref1) describes a preimage attack, just implement it.

**Reference**  
<a id="ezHash-ref1">[1]</a> Petit, Christophe, Kristin Lauter, and Jean-Jacques Quisquater. "Full cryptanalysis of LPS and Morgenstern hash functions." *International Conference on Security and Cryptography for Networks*. Springer, Berlin, Heidelberg, 2008.

### ezRSA
Category: Crypto  
Difficulty: ★★  
Solved: **11 / 12**  
Tag: **RSA, Hint**  

#### Details

[Source](0CTF-TCTF-2021-Finals/ezRSA/)

The script generates a CRT-RSA key pair, where `n` is 2000 bits, `e` is 1000 bits,  `dp`, `dq`, `k`, `l` are only 60 bits, then encrypt the flag. We are given the public key, encrypted flag and the lowest 10 bits of both `dp`  `dq` as well as a magic number `m = 1337 * k ** 4 + 7331 * l ** 3 + 73331 * k ** 2 + 13337 * l ** 2 + 7 * k * l + 2 * k + l`. 

#### Solution
Take 4th root of `m // 1337` may get an approximation of `k`, then search in a small range, for each candidate `k_bar`, take 3th root of `(m - 1337 * k_bar ** 4) // 7331` to get an approximation of `l`, then search again and use `m` to determine `l` and `k`. As `k * p - k = e * dp - 1`, we can recover `p`, then decrypt flag.  


<a id="ezRSA+"></a>
### ezRSA+
Category: Crypto  
Difficulty: ★★☆  
Solved:  **6 / 12**  
Tag: **RSA, Lattice, Continued Fraction**  

#### Details

[Source](0CTF-TCTF-2021-Finals/ezRSA+/)

Same as **ezRSA**, but no magic numebr `m`, and we get the lowest 12 bits of both `dp`  `dq`.

#### Solution

- Approach 1: After some arithmetic, we have `e * e * X + e * Y + Z = W * n`, where `X = dp * dq`,`Y = dp * (l - 1) + dq * (k - 1)`, `Z = (k - 1) * (l - 1)`, `W = k * l`.  Notice that `X, Y, Z, W` are small enough, so we can construct a lattice where the first column is `[n, -e^2, -e]`, then apply LLL to get `k` and `l`, which leads to factor `n`. 
- Approach 2: Notice `dp` and `dq` are small enough, we may apply [Wiener's attack](https://en.wikipedia.org/wiki/Wiener's_attack), to get `X = dp * dq` (for data in this task, `X = dp * dq // 3`) from the continued fraction of `e * e / N`. Then we may guess `dp` from the factors of `X`, and recover `p` via `GCD(pow(pow(2, e, n), dp, n) - 2, n)` .

- Approach 3: Both the above methods are unintended, intended solution involves a Partial Key Exposure attack on CRT-RSA [[1]](#ezRSA-ref1) or a small CRT-Exponent attack (slower) [[2]](#ezRSA-ref2).

**Reference**  
<a id="ezRSA-ref1">[1]</a> May, Alexander, Julian Nowakowski, and Santanu Sarkar. "Partial Key Exposure Attack on Short Secret Exponent CRT-RSA.  
<a id="ezRSA-ref2">[2]</a> Takayasu, Atsushi, Yao Lu, and Liqiang Peng. "Small CRT-exponent RSA revisited." Journal of Cryptology 32.4 (2019): 1337-1382.

### halfhalf
Category: Reverse  
Difficulty: ★★☆  
Solved: **7 / 12**  
Tag: **Rust, Jacobi Symbol**

#### Details

[Source](0CTF-TCTF-2021-Finals/halfhalf/)

We are given a Rust ELF file. It requires you solve a PoW, then input a magic word, next the server will generate a RSA key and a secret number. You can interact with server, there are five options: Get the RSA modulus; Guess the secret; Reset secret; Get flag; Exit. Each time you input a guess, the server may encrypt`9x^2` or `18x^2` for some random `x`, which depends whether your guess is greater than the secret. And if your guess is same as the secret you may get the flag. Note that all the number should be encoded with emoji.

#### Solution

The PoW requires us to find a 4-byte phrase whose sha256 digest match the given value for the last 3 bytes. And it is easy to find the magic word, which are a series of emoji. To distinguish `9x^2` and `18x^2`, we can compute its Jacobi symbol, so a binary search can determine the secret and get the flag. 

#### Issues

- I deployed this challenge with xinetd, due to a mistake in the wrapper, the program is executed under root directory, so it can't read the flag from file. Thanks @FORMALIN for pointing out this.
- @RBTree tells me the 60s time limitation is too tight, and he asks to increase it. But the source code of this challenge is lost, due to a VM broken, so the only way is to patch the binary. And he quickly finds the location of the corresponding parameters, then I patch it from 60s to 200s. Thanks RBTree's help. 

<a id="0CTF/TCTF-2021-Quals"></a>

## 0CTF/TCTF 2021 Quals
<a id="zer0lfsr-"></a>
### zer0lfsr-
Category: **Crypto**  
Difficulty: ★★  
Solved: **35 / 464**  
Tag: **LFSR, NFSR, Z3**  

#### Details

[Source](0CTF-TCTF-2021-Quals/zer0lfsr-/)

There are three generators composed of LFSR or NFSR.

- Generator1 contains a 48-bit NFSR and a 16-bit LFSR

- Generator2 contains a 16-bit NFSR and a 48-bit LFSR

- Generator3 contains a 64-bit LFSR

The output functions of each generator are filted, which are not linear from its internal state. We are asked to recover the initial state of any two generators within 50 seconds after obtained its consecutive 5000-byte output and the hash digest of its initial state. 

#### Solution

Most teams choose to attack Generator1 and Generator3.

- Approach 1: Use z3
- Approach 2: See [rkm's writeup](https://rkm0959.tistory.com/229?category=765103) for details 

<a id="zer0lfsr+"></a> 
###  zer0lfsr+
Category: **Crypto**  
Difficulty: ★★★★  
Solved: **2 / 464**  
Tag: **LFSR, NFSR, FCA**  

#### Details

[Source](0CTF-TCTF-2021-Quals/zer0lfsr+/)

The three generators remain unchanged. But we are given 20000 bytes from the majority function of the output of three generators, and are required to recover all the initial states within 100s. The initial state of Generator2 is derived from Generator1 with KDF function, the initial state of Generator3 is derived from Generator2 with KDF function.

#### Solution

Please check [rkm's writeup](https://rkm0959.tistory.com/229?category=765103) for details.

<a id="zer0lfsr++"></a>

### zer0lfsr++
Category: **Crypto**  
Difficulty: ★★★★★  
Solved: **1 / 464**  
Tag: **LFSR, NFSR, FCA**  

#### Details

[Source](0CTF-TCTF-2021-Quals/zer0lfsr++/)

Same as **zer0lfsr+**, but there are no KDF, three initial states are independent. And we have a hint, can get the highest 16 bits of one of the three state.

#### Solution

- FCA attack recover full state of Generator3.
- FCA attack recover the LFSR state of Generator2 and use the hint to get the NFSR state of Generator2. 
- Similar attack in [[1]](#zer0lfsr-ref1) to recover full state of Generator1.

**Reference**  
<a id="#zer0lfsr-ref1">[1]</a> Berbain, Côme, Henri Gilbert, and Alexander Maximov. "Cryptanalysis of grain." International Workshop on Fast Software Encryption. Springer, Berlin, Heidelberg, 2006.  