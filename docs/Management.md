# Management Interfaces

## HTTPS Management Interface

The turnserver process provides an HTTPS Web access as statistics and basic management
interface. The turnserver listens to incoming HTTPS admin connections on the same ports
as the main TURN/STUN listener. The Web admin pages are basic and self-explanatory.

To make the HTTPS interface active, the database table admin_user must be
populated with the admin user account(s). An admin user can be a superuser
(if not assigned to a particular realm) or a restricted user (if assigned to
a realm). The restricted admin users can perform only limited actions, within
their corresponding realms.

## Telnet CLI management interface

You have a telnet interface (enabled by default) to access the turnserver process, 
to view its state, to gather some statistical information, and to make some changes 
on-the-fly.

You can access that CLI interface with telnet or putty program (in telnet mode). 
The process by default listens to port 5766 on IP address 127.0.0.1 for the telnet
connections.

WARNING: all telnet communications are going unencrypted over the network. For
security reasons, we advise using the loopback IP addresses for CLI (127.0.0.1 
or ::1). The CLI may have a password configured, but that password is
transferred over the network unencrypted, too. So sticking to the local system
CLI access, and accessing the turnserver system terminal with ssh only, would 
be a wise decision.
