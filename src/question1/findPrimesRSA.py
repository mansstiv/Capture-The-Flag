#https://www.programiz.com/python-programming/examples/prime-number

def isPrime(num):
  flag = False
  if num > 1:
      for i in range(2, num):
          if (num % i) == 0:
              flag = True
              break
  if flag:
      return 0
  else:
      return 1

#https://www.dcode.fr/euler-totient
#From this site we found phi(127670779) = 127646784
import math

N=127670779

factors =[]
number=math.sqrt(127646784)
number = math.ceil(number)

number = int(number)

for i in range(number):
  if(127646784%(i+1)==0):
    factors.append(i+1)
    factors.append(int(127646784/(i+1)))

for x in range(len(factors)):
  factors[x]=factors[x]+1


possible_p=[]
possible_q=[]
count=0
for num in factors:
  a=isPrime(num)
  if(a==1):
    b=isPrime(factors[count+1])
    if(b==1):
      if(num<factors[count+1]):
        possible_p.append(num)
        possible_q.append(factors[count+1])

  count=count+1

for i in range(len(possible_p)):
  print("Possible p: ",possible_p[i]," possible q: ", possible_q[i]," p*q= ",possible_p[i]*possible_q[i])
  if(possible_p[i]*possible_q[i]==N):
    print("Correct p and q found")
    print("p: ", possible_p[i])
    print("q: ", possible_q[i])
