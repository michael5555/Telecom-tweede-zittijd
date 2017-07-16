Plaats de files in de folder elements in de elements/local folder in de click folder

Voer volgende commando's uit (vanuit de click-folder):
make elemlist 
make 

Om het scriptje te laten runnen voer je het volgende commando uit:
userlevel/click -p <port> <scripts-directory>/ipnetwork.click

In een 2e terminal (om input en output gescheiden te houden) voer je het volgende uit:
telnet localhost -p <port>

In de 2e terminal kan je nu clients laten joinen/leaven
gebruik handlers om join of leave uit te voeren. Deze worden met handlers uitgevoerd op het source element in de client.

Voorbeelden:
write <client>/source.join ADDR 239.0.0.0
write <client>/source.leave ADDR 239.0.0.0

ADDR staat voor het multicast address, wat in dit geval 239.0.0.0 MOET zijn.