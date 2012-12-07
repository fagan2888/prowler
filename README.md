# Send push notifications via Command Line

Tiny stand alone utility to send push notifications from scripts. Instead of sharing a configuration file the API_KEY gets backed in during the build/install. Just check it out from [via git](http://github.com/tcurdt/prowler/tree/master) and just install it.

    git clone git://github.com/tcurdt/prowler.git
    cd prowler
    make clean ; make API_KEY=YOUR_KEY_HERE install

Based on prowl for C by J. Dijkstra / abort@digitalise.net - buy him a beer if you meet him.
