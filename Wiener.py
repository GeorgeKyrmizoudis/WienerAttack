# -*- coding: utf-8 -*-
"""
Created on Sun Mar  6  2022

@author: George Kyrmizoudis

In this project we present an attack proposed by M.J.Wiener (M. Wiener. Cryptanalysis of short RSA secret exponents. IEEE Trans. Inform. Theory, 36(3):553-558, 1990.) 
on the well-known RSA cryptosystem. We briefly present the RSA algorithm (some formulae are written in LaTeX notation):
    
    1)Choose two prime numbers, p and q, and multiply them. The product N=pq is called  RSA modulus.
    2)Compute the value of Euler's totient function: $\phi(N)=(p-1)(q-1)=N-p-q+1$.
    3)Choose a number e which is coprime to N, i.e. $\gcd(e,N)=1$. This number (e) is called public exponent.
    4)Compute the number d which satisfies the equivalence: $ed\equiv1\pmod \phi(N)$. This number (d) is called private exponent. 
    5)Once computed, the pair (e,N) is published, whereas the tuple (d,p,q) must be kept secret! The pair (e,N) is called public key and the tuple (d,p,q) is called private key.
    6)Encryption: To encrypt your message m, compute $c\equiv m^{e}pmod N$ and send the encrypted message c. c is the so called encrypted message.
    7)Decryption: To decipher any encrypted message sent to you, compute $m\equiv c^{d}\pmod N$. Through this process you obtain the plaintext m.
    
    In 1990, M.J.Wiener proposed an attack on the RSA cryptosystem, utilizing the continued fractions algorithm (for short cfa) and Legendre's theorem. The attack is implemented as follows:

    1)We compute the partial quotients and the convergents of the rational number $\frac{e}{N}$.
    2) We take every denominator of the convergents that satisfies the inequality $d<\frac{1}{3}\sqrt[4]{N} (*)$ and we test if the private exponent is one of these $q_{i}$'s (there are two tests described below). 
    That means that Wiener attack is successful if d satisfies the inequality $d<\frac{1}{3}\sqrt[4]{N}$, that is d is less than one quater of the bits of the RSA modulus. For instance, if N is 64 bits long, d must be
    16 bits to be retrieved through Wiener attack.
    3) There are two tests to examine whether d is the appropriate secret exponent or not:
    
        First: We assume that $\phi(N)=N-p-q+1=\frac{eq_{i}-1}{p_{i}}$, where $\frac{p_{i}}{q_{i}}$ is a convergent of $\frac{e}{N}$. The next step is to solve the quadratic equation:
               $X^{2}-(N-\phi(N)+1)X+N=0$. If the equation has solutions (its discriminant is positive, i.e. $0<\Delta$, with $\sqrt{\Delta}\in\mathbb{Z}$, the solutions  may be the prime factors of the RSA modulus, p and q. 
               If the product of  solutions is not equal to N for this convergent, we examine the next one. However, if we perform every this test for every convergent that satisfies the condition (*), Wiener attack fails.
               
       Second: Another way to detect the appropriate denominator faster, is by examining if the equivalence $(x^{e})^{d}\equiv x\pmod N (**)$ is satisfied, where x is a random integer. In other words, we substitute $d=q_{i}$ and then we perform the test.
               If the current denominator is not the one, we test the next one. If not any of these $q_{i}$'s satisfies (**), then Wiener attack fails.
               
In this programme we present our suggestion for implementing Wiener attack, by presenting an instance of a public key. In order to speed up the process, we perform the second test to retrieve the private exponent. 

@Disclaimer-License: At this point, we clarify that we just perform a well known attack of  literature. In spite of this, if you wish, you can use this programme for own purpose. 

I hope that you find this programme enlightful and arises your interest in cryptography! Please, feel free to contact me for any reason! Enjoy programming!             
"""
from fractions import Fraction
import math

def main():
    (e,N)=(322645017,413429593)
    c= [222822385, 312745293, 192054566, 111711933, 405463276, 192054566, 177038067, 358067243, 358067243, 192054566,
309391167, 115503522, 79196718, 79196718, 340880818, 192054566, 312745293, 229294585, 192054566, 380238472, 79196718, 360069207]
    A=cont_frac(322645017,413429593)
    Conv=Convergents(322645017,413429593)
    print(f'The partial quotients of {Fraction(e,N)} are : {A}')
    print(f'The convergents of {Fraction(e,N)} are: {Conv}')
    print(f'We will apply the second test in order to identify the private exponent d.')
    d=Wiener_Attack(e,N)
    print(f'We test one by one every possible private exponent. We find out that the secret exponent is d={d}.')
    message(d,c,N)
    


def dectobin(a):
    '''this function converts a number from its decimal representation to its binary one'''
    a=int(a)
    if a==0:
        return [0]
    r = []
    while a > 0:
        q = a / 2
        b = a % 2
        r.append(int(b))
        if (a%2!=0) & (q!=1):
            q = q - 0.5
        a = q  
    r.reverse()
    return r
def square_and_multiply(a,c,b): 
    '''This function implements the square and multiply algotithm, so as to speed up the calculations'''
    z=1
    x=dectobin(c)
    for i in range(len(x)):
        j=len(x)-i-1
        if x[j]==1:
            z=(z*a)%b
        a=(a**2)%b
    return z


def cont_frac(p,q): 
    '''This function computes and outputs the partial quotients of the rational number in list form'''
    f=Fraction(p,q)
    a=[]
    if f==0:
        return 0
    else:
        i=0
        a.append(math.floor(f))
        f=f-a[i]
        while f>0:
            i=i+1
            a.append(math.floor(1/f))
            f=(1/f)-a[i]
    return a

def Convergents(p,q):               
    '''This function creates and outputs a list, which elements are the convergents  of the rational number p/q'''
    rep=cont_frac(p,q)              #Here the partial quotients of the rational number p/q are computed
    P=[]
    Q=[]  
    P.append(rep[0])                #p_0=a_0
    P.append(rep[0]*rep[1]+1)       #p_1=a_0*a_1+1
    Q.append(1)                     #q_0=1
    Q.append(rep[1])                #q_1=a_1
    Convergents=[]
    Convergents.append(Fraction(P[0],Q[0]))   
    Convergents.append(Fraction(P[1],Q[1]))   
    for i in range(2,len(rep)):
        P.append(rep[i]*P[i-1]+P[i-2])        #Here we compute the numerator of the i-th convergent
        Q.append(rep[i]*Q[i-1]+Q[i-2])        #Here we compute the denominator of the i-th convergent
        Convergents.append(Fraction(P[i],Q[i]))
    return Convergents

def Wiener_Attack(a,b): 
    '''This function performs the Wiener attack'''
    F=[]
    F=Convergents(a,b)
    for i in F:
        den=int(i.denominator)
        mul=den*a
        if square_and_multiply(2,mul,b)==2:
            return den
    return 'FAIL'

def decryption(c,d,N):  
    '''This function performs the decryption process. It also performs the decoding process, tranforming numbers to chars'''
    m=[]
    M=[]
    for i in c:
        m.append(square_and_multiply(i,d,N))
    for i in m:
        M.append(chr(i))
    return M

def message(d,c,N): 
    '''This function prints the appropriate message, according to the output of Wiener attack.''' 
    if d=='FAIL':
        print(f'Unfortunately, the Wiener attack fail. This is the reason why we cannot decipher  the encrypted message....' )
    else:
        m=decryption(c,d,N)
        print(f'The plaintext is {m}')

if __name__ == '__main__': main()
