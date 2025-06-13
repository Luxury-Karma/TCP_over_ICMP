TESTING ENVIRONEMENT I USE THIS FOR MY DEVs NOTE 

# TCP_over_ICMP
trying to generate a TCP type of protocol using ICMP


How will the connection work ? 

we will use the variable size of the payload inside of ICMP. Lets try to keep it at a minimal size quite making MORE packet than what TCP would do

TCP FLAGS : 
- s : syn
- a : ack
- z : syn,ack
- f : fin
- q : fin,ack 

the flag will need 1 byte.


for the sequance number and ack we will use hexa decimal which the max value is "7FFFFFFF" AKA 8 byte.


for the check sum we will use the function "check_sum" which will make all of it an hexadecimal. this should be holding inside of 3 byte


--- now this is to make the TCP protocol working ---


for the byte transfer I will start with 100 byte. This might be too large or not enough. we will see and we will need to adjust the check sum if needed. 


to split zone I will use "-^|^-" this is 5 bytes but it is highly unlikely to have this exact sequance of character anywhere else. Might make it smaller later.



so the ICMP traffic would look something like this : 


s-^|^-SEQUANCE_NUMBER-^|^-ACK_NUMBER-^|^-CHECK_SUM-^|^-PAYLOAD

1 byte-^|^-8 bytes-^|^-8 bytes-^|^-3 bytes-^|^-100 bytes

total of 120 bytes per packet. 
	- Later on I need to find a way to make the size of the packet dynamice but I need to find how to do it with char in C++ since the packet loader doesn't seem to like my strings. 