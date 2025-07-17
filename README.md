# MACs-message-authentication-codes
Post-Quantum Message Authentication Codes (MACs) and Performance Benchmarking.

This project presents a comparative performance analysis of newly proposed post-quantum secure Message Authentication Codes (MACs) in comparison to conventional MACs. 
The proposed constructions are designed with post-quantum cryptographic resilience in mind.

The correctness of the post-quantum MACs holds under the following parameter constraints:

   - m is an integer in the interval [2,21],

   - q is a prime number in the interval [m^2,m^3].

This repository includes:

    The implementation of the proposed post-quantum MAC schemes,

    Benchmark results comparing them with classical MACs (e.g., HMAC, CMAC)
    
https://ieeexplore.ieee.org/document/10794713 doi:10.1109/UNet62310.2024.10794713

