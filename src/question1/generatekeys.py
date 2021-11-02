dates_brute_force =[]

secrets_brute_force=[]

secrets_brute_force.append(" bigtent")
#secrets_brute_force.append(" onion")
#secrets_brute_force.append(" socat")
#secrets_brute_force.append(" onions")
#secrets_brute_force.append(" socat + onions")
#secrets_brute_force.append(" socat + onions = perfect recipe")
#secrets_brute_force.append(" DOG WHISTLE")
#secrets_brute_force.append(" THE XKCD PHONE 4")
#secrets_brute_force.append(" THE 10KCD PHONE 4")
#secrets_brute_force.append(" THE XKCD PHONE IV")
#secrets_brute_force.append(" THE XKCD PHONE IV")
#secrets_brute_force.append(" Yvoni Sarxeiopoulou")
#secrets_brute_force.append(" YS13")
#secrets_brute_force.append(" message")
#secrets_brute_force.append(" Giorgos Komninos")








for month in range (1,3):
  for day in range(1,32,1):
    if (day < 10):
      my_str="2021-0"+str(month)+"-0"+str(day)
    else:
      my_str="2021-0"+str(month)+"-"+str(day)
    dates_brute_force.append(my_str)
    #print(my_str)


keys_brute_force=[]
for i in dates_brute_force:
  for j in secrets_brute_force:
    my_str=i+j
    keys_brute_force.append(my_str)


import hashlib

keys_as_hex=[]
for i in keys_brute_force:
  h=hashlib.new('sha256')
  h.update(bytes(i,"ascii"))
  if (h.hexdigest().startswith("a7a7bf50cb3")):
    print(i)
  keys_as_hex.append(h.hexdigest())


textfile = open("hex_keys", "w")
for element in keys_as_hex:
    textfile. write(element + "\n")
