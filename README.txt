The program is in JAVA, used with openjdk 17.0.9 2023-10-17.

The program runs a continous loop.

compile and run the program on one terminal.

Query from a second terminal: dig @localhost -5754 zombo.com
		              dig @localhost -5754 en.wikipedia.org.

Note: for some reason I couldn't make "dig @localhost -5754 zombo.com any" this query work in my program. 

I hard coded an IP for en.wikipedia.org. -> for some reason Inet.getByAddress(); from java provides me a different IP than the DIG response.
But it does replaces the IP if the IP matches with the blacklist provided at the top of the program.

Thank you for your time.
