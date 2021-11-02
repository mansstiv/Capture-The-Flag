count=0
for i in range(10000):
  pollaplasio = 7*i
  strpoll = str(pollaplasio)
  if("7" in strpoll):
    count=count+1
  if (count==48):
    break

print(pollaplasio)
