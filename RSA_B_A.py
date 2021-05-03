# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""



import hashlib
import binascii
import string
import os


def home_mod_exponent(x, y, n):
    """exponentiation modulaire: calcule (a**b)%n"""
    R1 = 1
    R2 = x
    R3 = y
    while R3>0:
        if R3&1==1:
            R1 = (R1*R2)%n
        R2 = (R2*R2)%n
        R3 = R3>>1
    return R1
    



def home_ext_euclide(phi,e): #algorithme d'euclide étendu pour la recherche de l'exposant secret
# à compléter
    counter = 2
    sauv = phi
    swapV = 0
    V = [0,1,0]
    while(phi%e != 0):
        swapV = e
        V[2] = V[0] - (phi//e)*V[1]
        e = phi%e
        phi = swapV
        V[0] = V[1]
        V[1] = V[2]
        counter = counter + 1
    return (V[2]%sauv)

def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)


def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt


def motunlimitedchar(): #entrer le secret
    secret=input("donner un secret,aucune longeur maximum maximum : ")
    return(secret)

def xor(a,b):
    return ((~(a) & b) |(a & ~(b)))
 

#voici les éléments de la clé d'Alice
x1a=2010942103422233250095259520183 #p
x2a=3503815992030544427564583819137 #q
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=17 #exposant public
da=home_ext_euclide(phia,ea) #exposant privé

#voici les éléments de la clé de bob
x1b=9434659759111223227678316435911 #p
x2b=8842546075387759637728590482297 #q
nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=23 # exposants public
db=home_ext_euclide(phib,eb) #exposant privé


print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre précieux secret")
print("d =",db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x=input("appuyer sur entrer")
secret=motunlimitedchar()

#On découpe le secret en plusieurs blocs

tableauBlocNonChiffre = []
for i in range(0,len(secret)//20+1,1):
    tableauBlocNonChiffre.append(home_string_to_int(secret[20*i:20*(i+1)]))
print("*******************************************************************")
print("voici la version en nombre décimal de ",secret," : ")
print(tableauBlocNonChiffre)

#On passe maintenant à l'opérationd de CBC

tableauBlocChiffre = []
fichierStat = os.stat("RSA_B_A.py")
vecteurInitialization = fichierStat.st_ino
tableauBlocChiffre.append(home_mod_exponent(xor(vecteurInitialization, tableauBlocNonChiffre[0]), ea, na))
for i in range(1,len(tableauBlocNonChiffre)):
    tableauBlocChiffre.append(home_mod_exponent(xor(tableauBlocChiffre[i-1], tableauBlocNonChiffre[i]), ea, na))
print("voici le message découpé en bloc CBC chiffré avec la publique d'Alice : ")
print(tableauBlocChiffre)

#On chiffre également le vecteur d'initialisation pour l'envoyer à Alice

vecteurInitializationChiffre = home_mod_exponent(vecteurInitialization, ea, na)

#On hash avec MD5 tous les blocs(non chiffre par CBC)

print("*******************************************************************")
print("On utilise la fonction de hashage MDA5 pour obtenir le hash du message",secret)
Bhachis3 = []
for i in range(len(tableauBlocNonChiffre)):
    Bhachis0=hashlib.md5(str(tableauBlocNonChiffre[i]).encode(encoding='UTF-8')).digest() #MD5 du message
    Bhachis1=binascii.b2a_uu(Bhachis0)
    Bhachis2=Bhachis1.decode() #en string
    Bhachis3.append(home_string_to_int(Bhachis2))
print("voici le hash en nombre décimal "), # On n'utilise pas la fonctionde hashage sha256 car celle ci renvoi une valeur trop grande par rapport à n
print(Bhachis3)

#BOB signe tous les blocs qui viennent d'etre haché

print("voici la signature avec la clé privée de Bob du hachis")
signe = []
for i in range(len(Bhachis3)):
    mx1b = home_mod_exponent(Bhachis3[i], db, x1b) #utilisation du theoreme du reste chinois
    mx2b = home_mod_exponent(Bhachis3[i], db, x2b)
    inversex1b = home_ext_euclide(x2b,x1b)
    h = ((mx2b-mx1b)*inversex1b)%x2b
    signe.append((mx1b+h*x1b)%nb)
print(signe)


#Opération d'envoi

print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice,decouper en bloc \n",tableauBlocChiffre,"\n \t 2-le hash signé \n",signe,"\n \t 3- et le vecteur d'initialisation chiffré \n",vecteurInitializationChiffre)
print("*******************************************************************")
x=input("appuyer sur entrer")
print("*******************************************************************")

#Alice commence par dechiffrer le vecteur d'initialisation

vecteurInitializationAlice = home_mod_exponent(vecteurInitializationChiffre, da, na)

#Alice utilise la bijection de CBC ici pour retrouver les blocs en clairs

dechif = []
print("Alice déchiffre le message chiffré découpé en bloc \n",tableauBlocChiffre,"\nce qui donne ")
mx1a = home_mod_exponent(tableauBlocChiffre[0], da, x1a) #utilisation du theoreme de reste chinois
mx2a = home_mod_exponent(tableauBlocChiffre[0], da, x2a)
inversex1a = home_ext_euclide(x2a, x1a)
h = ((mx2a-mx1a)*inversex1a)%x2a
dechif.append(xor((mx1a+h*x1a)%na,vecteurInitializationAlice))
for i in range(1,len(tableauBlocChiffre)):
    mx1a = home_mod_exponent(tableauBlocChiffre[i], da, x1a) #utilisation du theoreme de reste chinois
    mx2a = home_mod_exponent(tableauBlocChiffre[i], da, x2a)
    inversex1a = home_ext_euclide(x2a, x1a)
    h = ((mx2a-mx1a)*inversex1a)%x2a
    dechif.append(xor((mx1a+h*x1a)%na,tableauBlocChiffre[i-1]))
print(dechif)

#Pour chaque bloc de message signe, Alice le dechiffre avec la cle public de Bob, le résultat est donc un tableau de messages qui sont juste hashés

print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n",signe,"\n ce qui donne  en décimal")
designe = []
for i in range(len(signe)):
    designe.append(home_mod_exponent(signe[i], eb, nb))
print(designe)

#Alice hash dechif pour voir si elle obtient la même chose que design

print("Alice vérifie si elle obtient la même chose avec le hash de ",dechif)
Ahachis3 = []
for i in range(len(dechif)):
    Ahachis0=hashlib.md5(str(dechif[i]).encode(encoding='UTF-8',errors='strict')).digest()
    Ahachis1=binascii.b2a_uu(Ahachis0)
    Ahachis2=Ahachis1.decode()
    Ahachis3.append(home_string_to_int(Ahachis2))
print(Ahachis3)

#Il faut que cela soit égal pour chaque bloc

counter = 0
for i in range(len(designe)):
    if(designe[i] == Ahachis3[i]):
        counter += 1

if (counter == len(designe)):
    messageEnvoye = home_int_to_string(dechif[0])
    for i in range(1,len(dechif)):
        messageEnvoye = messageEnvoye + home_int_to_string(dechif[i])
    print("Alice : Bob m'a envoyé : ",messageEnvoye)
else:
    print("oups, il y a un problème")