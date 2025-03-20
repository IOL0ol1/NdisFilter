BF4 NidsFilter
----

BF4's servers have a UDP protocol vulnerability, which makes it possible to use very little forged data to cause server lag.    
This project uses WinpkFilter to intercept the UDP port of the game service and filter invalid data in it.

How
----
1. First of all, you will need to rent a Battlefield4 game server from an EA designated server operator.  
2. Then you'll need to make sure that the backend management server and the game server are on the same physical host.    
3. Use the admin plugin [here](https://github.com/IOL0ol1/ProconPlugins/blob/master/RemoteManager/RemoteManager.cs) to get server permissions.
4. Install the WinpkFilter driver.
5. Run the binaries for this project.

Remark
----
Because there is a very obvious flaw in step 3, the backend management server and the game server are currently not on the same physical host.    
And it doesn't solve UDP flood attacks, which is actually the main way to attack.   
So this project doesn't make much sense at the moment, but the management plug-in can still get the host permissions of the backend management server.    
